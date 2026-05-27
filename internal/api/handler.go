package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"

	"gitee.com/yangdadayyds/uepcap/internal/job"
)

// Handler handles API requests
type Handler struct {
	jobMgr       *job.Manager
	messageStats *messageStatsCacheStore
	analysis     *analysisCacheStore
	imsiScans    map[string]*imsiScanCall
	imsiScanMu   sync.Mutex
}

type imsiScanCall struct {
	done  chan struct{}
	imsis []string
	err   error
}

// NewHandler creates a new API handler
func NewHandler(jobMgr *job.Manager) *Handler {
	return &Handler{
		jobMgr:       jobMgr,
		messageStats: newMessageStatsCacheStore(),
		analysis:     newAnalysisCacheStore(128),
		imsiScans:    make(map[string]*imsiScanCall),
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
	mux.HandleFunc("POST /api/jobs/{id}/message-stats/stream", h.StreamMessageStats)
	mux.HandleFunc("POST /api/jobs/{id}/ngap-messages", h.GetNGAPMessages)
	mux.HandleFunc("POST /api/jobs/{id}/ngap-messages/stream", h.StreamNGAPMessages)
	mux.HandleFunc("POST /api/jobs/{id}/s1ap-messages", h.GetS1APMessages)
	mux.HandleFunc("POST /api/jobs/{id}/s1ap-messages/stream", h.StreamS1APMessages)
	mux.HandleFunc("POST /api/jobs/{id}/nas-messages", h.GetNASMessages)
	mux.HandleFunc("POST /api/jobs/{id}/nas-messages/stream", h.StreamNASMessages)
	mux.HandleFunc("POST /api/jobs/{id}/sm-nas-messages", h.GetSMNASMessages)
	mux.HandleFunc("POST /api/jobs/{id}/sm-nas-messages/stream", h.StreamSMNASMessages)
	mux.HandleFunc("POST /api/jobs/{id}/s11-messages", h.GetS11Messages)
	mux.HandleFunc("POST /api/jobs/{id}/s11-messages/stream", h.StreamS11Messages)

	// PFCP session transaction analysis operations
	mux.HandleFunc("POST /api/jobs/{id}/pfcp-sessions", h.GetPFCPSessions)
	mux.HandleFunc("POST /api/jobs/{id}/pfcp-sessions/stream", h.StreamPFCPSessions)

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

func decodeOptionalJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	err := json.NewDecoder(r.Body).Decode(dst)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
