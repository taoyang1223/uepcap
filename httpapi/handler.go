// Package httpapi provides an embeddable HTTP API for uepcap.
//
// This package allows external Go projects to embed uepcap's HTTP API
// into their own HTTP servers with minimal configuration.
//
// # Quick Start
//
//	mux := http.NewServeMux()
//	h, err := httpapi.New(uepcap.Config{
//	    DataDir: "./data",
//	    JobTTL:  time.Hour,
//	    MaxJobs: 3,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	h.RegisterRoutes(mux)
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	h.Start(ctx)
//	http.ListenAndServe(":8080", mux)
//
// # API Routes
//
// The following routes are registered:
//
// Job Management:
//   - POST /api/jobs          - Upload PCAP files and create a job
//   - GET  /api/jobs          - List all jobs
//   - GET  /api/jobs/{id}     - Get job details
//   - DELETE /api/jobs/{id}   - Delete a job
//
// IMSI Operations:
//   - GET /api/jobs/{id}/imsis        - Scan and return IMSI list
//   - GET /api/jobs/{id}/imsis/stream - SSE stream for real-time IMSI updates
//
// Export Operations:
//   - POST /api/jobs/{id}/export              - Export filtered packets (async)
//   - GET  /api/jobs/{id}/export/{taskId}/status - Get export task status
//   - GET  /api/jobs/{id}/download/{filename} - Download exported file
//   - POST /api/jobs/{id}/export/text         - Export packets as JSON text
//   - POST /api/jobs/{id}/export/text/download - Download packets as JSON
//
// Flow Analysis:
//   - POST /api/jobs/{id}/flow/brief          - Get brief flow summary
//   - POST /api/jobs/{id}/flow/generate       - Generate Mermaid flow diagram
//   - POST /api/jobs/{id}/flow/generate/stream - SSE stream for flow generation
//
// # Environment Variables
//
// The following environment variables are supported for LLM flow annotations:
//   - MOONSHOT_API_KEY  - API key for Moonshot LLM (optional)
//   - MOONSHOT_BASE_URL - Base URL for Moonshot API (default: https://api.moonshot.cn/v1)
//   - MOONSHOT_MODEL    - Model name to use (optional)
//
// # Runtime Dependencies
//
// Requires tshark and mergecap to be installed. See package uepcap for details.
package httpapi

import (
	"context"
	"net/http"

	uepcap "gitee.com/yangdadayyds/uepcap"
)

// Handler provides HTTP API handlers for uepcap functionality.
// Use New() to create a Handler, then call RegisterRoutes() to add
// routes to your HTTP mux, and Start() to begin background processing.
type Handler struct {
	app *uepcap.App
}

// New creates a new HTTP API handler with the given configuration.
// This initializes the uepcap application and validates dependencies.
func New(cfg uepcap.Config) (*Handler, error) {
	app, err := uepcap.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{app: app}, nil
}

// NewFromApp creates a Handler from an existing uepcap.App instance.
// Use this if you need to share the App instance with other code.
func NewFromApp(app *uepcap.App) *Handler {
	return &Handler{app: app}
}

// RegisterRoutes registers all uepcap HTTP API routes on the provided mux.
// Routes are registered under /api/... path prefix.
//
// The mux should be a *http.ServeMux or compatible router that supports
// Go 1.22+ method patterns (e.g., "POST /api/jobs").
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	h.app.Handler().RegisterRoutes(mux)
}

// Start begins background cleanup routines for job management.
// This should be called after RegisterRoutes() and before serving requests.
// The routines will run until the provided context is cancelled.
func (h *Handler) Start(ctx context.Context) {
	h.app.Start(ctx)
}

// Stop cancels background routines.
// This is automatically called if the context passed to Start is cancelled.
func (h *Handler) Stop() {
	h.app.Stop()
}

// App returns the underlying uepcap.App instance.
// Use this for direct access to programmatic APIs.
func (h *Handler) App() *uepcap.App {
	return h.app
}

