package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
)

type PFCPSessionRequest struct {
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

func (h *Handler) GetPFCPSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req PFCPSessionRequest
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	analyzer := pfcpsession.NewAnalyzer()
	if req.TimeoutSeconds > 0 {
		analyzer.SetTimeout(time.Duration(req.TimeoutSeconds) * time.Second)
	}

	result, err := analyzer.AnalyzeFile(ctx, job.MergedPcap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result.Filename = displayPcapFilename(job.OriginalFiles, job.MergedPcap)

	writeSuccess(w, result)
}

func displayPcapFilename(originalFiles []string, fallback string) string {
	if len(originalFiles) == 0 {
		return filepath.Base(fallback)
	}
	names := make([]string, 0, len(originalFiles))
	for _, file := range originalFiles {
		name := filepath.Base(file)
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return filepath.Base(fallback)
	}
	if len(names) == 1 {
		return names[0]
	}
	return fmt.Sprintf("%d files: %s", len(names), strings.Join(names, ", "))
}
