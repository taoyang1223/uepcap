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
	BatchRows          int    `json:"batch_rows,omitempty"`
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
	value, err := h.analysis.getOrCompute(ctx, fmt.Sprintf("%s|pfcp-transaction-v10|timeout=%d", id, timeoutSeconds), func(ctx context.Context) (any, error) {
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

func (h *Handler) StreamPFCPSessions(w http.ResponseWriter, r *http.Request) {
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

	flusher, ok := prepareEventStream(w)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	timeoutSeconds := req.TimeoutSeconds
	cacheKey := fmt.Sprintf("%s|pfcp-transaction-v10-stream|timeout=%d", id, timeoutSeconds)
	if value, ok := h.analysis.get(cacheKey); ok {
		if result, ok := value.(*pfcpsession.AnalysisResult); ok {
			sendSSEEvent(w, flusher, "done", map[string]any{
				"progress": pfcpsession.StreamProgress{Done: true},
				"result":   windowPFCPAnalysis(result, normalizedAnalysisLimit(req.Limit), req.ResponseTimeFilter),
				"cached":   true,
			})
			return
		}
	}

	sendSSEEvent(w, flusher, "progress", map[string]any{
		"phase": "analyzing",
	})

	analyzer := pfcpsession.NewAnalyzer()
	if timeoutSeconds > 0 {
		analyzer.SetTimeout(time.Duration(timeoutSeconds) * time.Second)
	}
	result, err := analyzer.AnalyzeFileStream(r.Context(), job.MergedPcap, normalizedStreamBatchRows(req.BatchRows), func(progress pfcpsession.StreamProgress, result *pfcpsession.AnalysisResult) error {
		result.Filename = displayPcapFilename(job.OriginalFiles, job.MergedPcap)
		out := windowPFCPAnalysis(result, normalizedAnalysisLimit(req.Limit), req.ResponseTimeFilter)
		event := "partial_result"
		if progress.Done {
			event = "done"
		}
		sendSSEEvent(w, flusher, event, map[string]any{
			"progress": progress,
			"result":   out,
		})
		return nil
	})
	if err != nil {
		sendSSEEvent(w, flusher, "error", err.Error())
		return
	}
	result.Filename = displayPcapFilename(job.OriginalFiles, job.MergedPcap)
	h.analysis.set(cacheKey, result)
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
