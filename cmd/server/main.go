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
	"path"
	"strings"
	"syscall"
	"time"

	uepcap "gitee.com/yangdadayyds/uepcap"
	"gitee.com/yangdadayyds/uepcap/httpapi"
	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

//go:embed all:dist
var webFS embed.FS

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	dataDir := flag.String("data", "./data", "Data directory for temporary files")
	ttl := flag.Duration("ttl", 1*time.Hour, "Job TTL (e.g., 1h, 30m)")
	maxJobs := flag.Int("max-jobs", 20, "Maximum number of jobs to keep (0 = unlimited)")
	maxTshark := flag.Int("max-tshark", 0, "Maximum concurrent tshark/mergecap processes (0 = auto)")
	flag.Parse()

	tshark.SetMaxConcurrentProcesses(*maxTshark)

	// Initialize uepcap handler using the public httpapi package
	// This demonstrates how external projects would embed uepcap
	handler, err := httpapi.New(uepcap.Config{
		DataDir: *dataDir,
		JobTTL:  *ttl,
		MaxJobs: *maxJobs,
		// Dependencies are checked automatically by httpapi.New()
	})
	if err != nil {
		log.Fatalf("Failed to initialize uepcap: %v", err)
	}

	// Start background cleanup routines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler.Start(ctx)

	// Setup HTTP routes
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

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
	log.Printf("Max concurrent tshark/mergecap: %d", tshark.MaxConcurrentProcesses())
	if *maxJobs > 0 {
		log.Printf("Max jobs: %d (auto-cleanup enabled)", *maxJobs)
	} else {
		log.Printf("Max jobs: unlimited")
	}
	log.Println("========================================")
	log.Printf("🚀 Server started on port %d", *port)
	log.Printf("👉 Access URL: http://localhost:%d", *port)
	log.Println("========================================")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Server stopped")
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
			setStaticCacheHeaders(w, path)
			fileServer.ServeHTTP(w, r)
			return
		}

		if fallback, ok := findAssetFallback(fsys, path); ok {
			setStaticCacheHeaders(w, fallback)
			http.ServeFileFS(w, r, fsys, fallback)
			return
		}

		// For SPA: serve index.html for non-existent paths (except /api)
		if len(r.URL.Path) < 4 || r.URL.Path[:4] != "/api" {
			r.URL.Path = "/"
			setStaticCacheHeaders(w, "index.html")
			fileServer.ServeHTTP(w, r)
			return
		}

		http.NotFound(w, r)
	})
}

func setStaticCacheHeaders(w http.ResponseWriter, path string) {
	if path == "index.html" || path == "/" {
		w.Header().Set("Cache-Control", "no-cache")
		return
	}
	if strings.HasPrefix(path, "assets/") {
		w.Header().Set("Cache-Control", "no-cache")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
}

func findAssetFallback(fsys fs.FS, requested string) (string, bool) {
	if !strings.HasPrefix(requested, "assets/") || (!strings.HasSuffix(requested, ".js") && !strings.HasSuffix(requested, ".css")) {
		return "", false
	}

	name := path.Base(requested)
	dash := strings.IndexByte(name, '-')
	dot := strings.LastIndexByte(name, '.')
	if dash <= 0 || dot <= dash {
		return "", false
	}
	prefix := name[:dash+1]
	suffix := name[dot:]

	entries, err := fs.ReadDir(fsys, "assets")
	if err != nil {
		return "", false
	}
	for _, entry := range entries {
		candidate := entry.Name()
		if !entry.IsDir() && strings.HasPrefix(candidate, prefix) && strings.HasSuffix(candidate, suffix) {
			return "assets/" + candidate, true
		}
	}
	return "", false
}
