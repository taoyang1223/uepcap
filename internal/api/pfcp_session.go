package api

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
)

type PFCPSessionRequest struct {
	TimeoutSeconds     int    `json:"timeout_seconds,omitempty"`
	Limit              int    `json:"limit,omitempty"`
	ResponseTimeFilter string `json:"response_time_filter,omitempty"`
}

func (h *Handler) GetPFCPSessions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req PFCPSessionRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	timeoutSeconds := req.TimeoutSeconds
	value, err := h.analysis.getOrCompute(ctx, fmt.Sprintf("%s|pfcp-transaction-v4|timeout=%d", id, timeoutSeconds), func(ctx context.Context) (any, error) {
		analyzer := pfcpsession.NewAnalyzer()
		if timeoutSeconds > 0 {
			analyzer.SetTimeout(time.Duration(timeoutSeconds) * time.Second)
		}
		result, err := analyzer.AnalyzeFile(ctx, job.MergedPcap)
		if err != nil {
			return nil, err
		}
		result.Filename = displayPcapFilename(job.OriginalFiles, job.MergedPcap)
		return result, nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result, ok := value.(*pfcpsession.AnalysisResult)
	if !ok {
		writeError(w, http.StatusInternalServerError, "invalid PFCP analysis result")
		return
	}

	out := windowPFCPAnalysis(result, normalizedAnalysisLimit(req.Limit), req.ResponseTimeFilter)
	writeSuccess(w, out)
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
