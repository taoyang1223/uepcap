package api

import (
	"encoding/json"
	"net/http"

	"gitee.com/yangdadayyds/uepcap/internal/job"
)

// Handler handles API requests
type Handler struct {
	jobMgr *job.Manager
}

// NewHandler creates a new API handler
func NewHandler(jobMgr *job.Manager) *Handler {
	return &Handler{
		jobMgr: jobMgr,
	}
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

	// Export packets as text (JSON)
	mux.HandleFunc("POST /api/jobs/{id}/export/text", h.ExportPacketsText)
	mux.HandleFunc("POST /api/jobs/{id}/export/text/download", h.DownloadPacketsText)

	// Message statistics operations
	mux.HandleFunc("POST /api/jobs/{id}/message-stats", h.GetMessageStats)
	mux.HandleFunc("POST /api/jobs/{id}/ngap-messages", h.GetNGAPMessages)
	mux.HandleFunc("POST /api/jobs/{id}/nas-messages", h.GetNASMessages)
	mux.HandleFunc("POST /api/jobs/{id}/s11-messages", h.GetS11Messages)

	// PFCP session transaction analysis operations
	mux.HandleFunc("POST /api/jobs/{id}/pfcp-sessions", h.GetPFCPSessions)

	// Flow analysis operations
	mux.HandleFunc("POST /api/jobs/{id}/flow/brief", h.GetFlowBrief)
	mux.HandleFunc("POST /api/jobs/{id}/flow/generate", h.GenerateFlow)
	mux.HandleFunc("POST /api/jobs/{id}/flow/generate/stream", h.GenerateFlowStream)

	// Packet tree (protocol details) operations
	mux.HandleFunc("GET /api/jobs/{id}/packets/{frame}/tree", h.GetPacketTree)
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
