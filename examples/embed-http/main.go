// Example: Embedding uepcap HTTP API in your Go application
//
// This example demonstrates how to integrate uepcap's PCAP analysis
// capabilities into an existing HTTP server with just a few lines of code.
//
// Prerequisites:
//   - tshark and mergecap must be installed (apt install wireshark-cli)
//
// Run:
//
//	go run main.go
//
// Then access http://localhost:8080/api/jobs to verify the API is working.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	uepcap "gitee.com/yangdadayyds/uepcap"
	"gitee.com/yangdadayyds/uepcap/httpapi"
)

func main() {
	// Step 1: Create the uepcap HTTP handler with your configuration
	handler, err := httpapi.New(uepcap.Config{
		DataDir: "./data",         // Where to store job data
		JobTTL:  time.Hour,        // Auto-cleanup jobs after 1 hour
		MaxJobs: 5,                // Keep at most 5 jobs
		// Moonshot LLM config (optional, for flow annotations)
		// Can also be set via MOONSHOT_API_KEY environment variable
	})
	if err != nil {
		log.Fatalf("Failed to initialize uepcap: %v", err)
	}

	// Step 2: Start background cleanup routines
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler.Start(ctx)

	// Step 3: Create your HTTP mux and register uepcap routes
	mux := http.NewServeMux()

	// Register uepcap API routes under /api/...
	handler.RegisterRoutes(mux)

	// You can add your own routes alongside uepcap's
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
<!DOCTYPE html>
<html>
<head><title>uepcap Embedded Example</title></head>
<body>
	<h1>uepcap HTTP API is running!</h1>
	<p>Try these endpoints:</p>
	<ul>
		<li><a href="/api/jobs">GET /api/jobs</a> - List all jobs</li>
		<li>POST /api/jobs - Upload PCAP file(s)</li>
		<li>GET /api/jobs/{id}/imsis - Get IMSI list</li>
	</ul>
	<h2>Example: Upload a PCAP file</h2>
	<pre>curl -F "files=@your-file.pcap" http://localhost:8080/api/jobs</pre>
</body>
</html>
		`))
	})

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Step 4: Create and start the HTTP server
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Minute, // Long timeout for large exports
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	log.Println("Server starting on http://localhost:8080")
	log.Println("uepcap API available at /api/...")
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

