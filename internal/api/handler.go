package api

import (
	"encoding/json"
	"net/http"

	"uepcap/internal/job"
)

// Handler handles API requests
type Handler struct {
	jobMgr *job.Manager
}

// NewHandler creates a new API handler
func NewHandler(jobMgr *job.Manager) *Handler {
	return &Handler{jobMgr: jobMgr}
}

// RegisterRoutes registers API routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Job management
	mux.HandleFunc("POST /api/jobs", h.CreateJob)
	mux.HandleFunc("GET /api/jobs", h.ListJobs)
	mux.HandleFunc("GET /api/jobs/{id}", h.GetJob)
	mux.HandleFunc("DELETE /api/jobs/{id}", h.DeleteJob)

	// IMSI operations
	mux.HandleFunc("GET /api/jobs/{id}/imsis", h.GetIMSIList)
	mux.HandleFunc("GET /api/jobs/{id}/imsis/stream", h.StreamIMSIList)

	// Export operations
	mux.HandleFunc("POST /api/jobs/{id}/export", h.ExportPackets)
	mux.HandleFunc("GET /api/jobs/{id}/export/{taskId}/status", h.GetExportStatus)
	mux.HandleFunc("GET /api/jobs/{id}/download/{filename}", h.DownloadExport)
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// writeJSON writes JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeSuccess writes a success response
func writeSuccess(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, APIResponse{Success: true, Data: data})
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, err string) {
	writeJSON(w, status, APIResponse{Success: false, Error: err})
}
