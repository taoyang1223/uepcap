package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"uepcap/internal/api"
	"uepcap/internal/job"
	"uepcap/internal/tshark"
)

//go:embed all:dist
var webFS embed.FS

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	dataDir := flag.String("data", "./data", "Data directory for temporary files")
	ttl := flag.Duration("ttl", 1*time.Hour, "Job TTL (e.g., 1h, 30m)")
	flag.Parse()

	// Check dependencies
	if err := checkDependencies(); err != nil {
		log.Fatalf("Dependency check failed: %v", err)
	}

	// Initialize job manager
	jobMgr := job.NewManager(*dataDir, *ttl)

	// Start TTL cleanup goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go jobMgr.StartCleanup(ctx, 5*time.Minute)

	// Setup HTTP routes
	mux := http.NewServeMux()
	apiHandler := api.NewHandler(jobMgr)
	apiHandler.RegisterRoutes(mux)

	// Serve static files from embedded FS
	distFS, err := fs.Sub(webFS, "dist")
	if err != nil {
		log.Printf("Warning: embedded web dist not found, frontend will not be served: %v", err)
	} else {
		fileServer := http.FileServer(http.FS(distFS))
		mux.Handle("/", spaHandler(fileServer, distFS))
	}

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Minute, // Long timeout for large file exports
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down server...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	log.Printf("Data directory: %s", *dataDir)
	log.Printf("Job TTL: %v", *ttl)
	log.Println("========================================")
	log.Printf("🚀 Server started on port %d", *port)
	log.Printf("👉 Access URL: http://localhost:%d", *port)
	log.Println("========================================")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Server stopped")
}

func checkDependencies() error {
	// Check tshark
	if err := tshark.CheckInstalled("tshark"); err != nil {
		return fmt.Errorf("tshark not found: %w (install wireshark-cli or wireshark)", err)
	}
	// Check mergecap
	if err := tshark.CheckInstalled("mergecap"); err != nil {
		return fmt.Errorf("mergecap not found: %w (install wireshark-cli or wireshark)", err)
	}
	log.Println("Dependencies OK: tshark, mergecap")
	return nil
}

// spaHandler wraps file server to support SPA routing (fallback to index.html)
func spaHandler(fileServer http.Handler, fsys fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "index.html"
		} else if path[0] == '/' {
			path = path[1:]
		}

		// Check if file exists
		if _, err := fs.Stat(fsys, path); err == nil {
			fileServer.ServeHTTP(w, r)
			return
		}

		// For SPA: serve index.html for non-existent paths (except /api)
		if len(r.URL.Path) < 4 || r.URL.Path[:4] != "/api" {
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}

		http.NotFound(w, r)
	})
}
