package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/analysisstream"
	"gitee.com/yangdadayyds/uepcap/internal/s11analyzer"
)

type S11MessagesRequest struct {
	Limit              int    `json:"limit,omitempty"`
	ResponseTimeFilter string `json:"response_time_filter,omitempty"`
	BatchRows          int    `json:"batch_rows,omitempty"`
}

func (h *Handler) GetS11Messages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req S11MessagesRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	value, err := h.analysis.getOrCompute(ctx, id+"|s11", func(ctx context.Context) (any, error) {
		result, err := s11analyzer.NewAnalyzer().AnalyzeFile(ctx, job.MergedPcap)
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

	result, ok := value.(*s11analyzer.AnalysisResult)
	if !ok {
		writeError(w, http.StatusInternalServerError, "invalid S11 analysis result")
		return
	}

	out := windowS11Analysis(result, normalizedAnalysisLimit(req.Limit), req.ResponseTimeFilter)
	writeSuccess(w, out)
}

func (h *Handler) StreamS11Messages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req S11MessagesRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	flusher, ok := prepareEventStream(w)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	cacheKey := id + "|s11-v2-stream"
	if value, ok := h.analysis.get(cacheKey); ok {
		if result, ok := value.(*s11analyzer.AnalysisResult); ok {
			sendSSEEvent(w, flusher, "done", map[string]any{
				"progress": analysisstream.Progress{Done: true},
				"result":   windowS11Analysis(result, normalizedAnalysisLimit(req.Limit), req.ResponseTimeFilter),
				"cached":   true,
			})
			return
		}
	}

	sendSSEEvent(w, flusher, "progress", map[string]any{"phase": "analyzing"})
	result, err := s11analyzer.NewAnalyzer().AnalyzeFileStream(r.Context(), job.MergedPcap, normalizedStreamBatchRows(req.BatchRows), func(progress analysisstream.Progress, result *s11analyzer.AnalysisResult) error {
		result.Filename = displayPcapFilename(job.OriginalFiles, job.MergedPcap)
		event := "partial_result"
		if progress.Done {
			event = "done"
		}
		sendSSEEvent(w, flusher, event, map[string]any{
			"progress": progress,
			"result":   windowS11Analysis(result, normalizedAnalysisLimit(req.Limit), req.ResponseTimeFilter),
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
