package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/analysisstream"
	"gitee.com/yangdadayyds/uepcap/internal/nasanalyzer"
)

type NASMessagesRequest struct {
	Limit     int `json:"limit,omitempty"`
	BatchRows int `json:"batch_rows,omitempty"`
}

func (h *Handler) GetNASMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req NASMessagesRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	value, err := h.analysis.getOrCompute(ctx, id+"|nas", func(ctx context.Context) (any, error) {
		result, err := nasanalyzer.NewAnalyzer().AnalyzeMMFile(ctx, job.MergedPcap)
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

	result, ok := value.(*nasanalyzer.AnalysisResult)
	if !ok {
		writeError(w, http.StatusInternalServerError, "invalid NAS analysis result")
		return
	}

	out := windowNASAnalysis(result, normalizedAnalysisLimit(req.Limit))
	writeSuccess(w, out)
}

func (h *Handler) StreamNASMessages(w http.ResponseWriter, r *http.Request) {
	h.streamNASMessages(w, r, false)
}

func (h *Handler) GetSMNASMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req NASMessagesRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	value, err := h.analysis.getOrCompute(ctx, id+"|sm-nas", func(ctx context.Context) (any, error) {
		result, err := nasanalyzer.NewAnalyzer().AnalyzeSMFile(ctx, job.MergedPcap)
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

	result, ok := value.(*nasanalyzer.AnalysisResult)
	if !ok {
		writeError(w, http.StatusInternalServerError, "invalid SM NAS analysis result")
		return
	}

	out := windowNASAnalysis(result, normalizedAnalysisLimit(req.Limit))
	writeSuccess(w, out)
}

func (h *Handler) StreamSMNASMessages(w http.ResponseWriter, r *http.Request) {
	h.streamNASMessages(w, r, true)
}

func (h *Handler) streamNASMessages(w http.ResponseWriter, r *http.Request, smOnly bool) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req NASMessagesRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	flusher, ok := prepareEventStream(w)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	cacheKey := id + "|nas-v2-stream"
	filter := func(result *nasanalyzer.AnalysisResult) *nasanalyzer.AnalysisResult {
		if smOnly {
			return nasanalyzer.FilterSMResult(result)
		}
		return nasanalyzer.FilterMMResult(result)
	}
	if value, ok := h.analysis.get(cacheKey); ok {
		if result, ok := value.(*nasanalyzer.AnalysisResult); ok {
			sendSSEEvent(w, flusher, "done", map[string]any{
				"progress": analysisstream.Progress{Done: true},
				"result":   windowNASAnalysis(filter(result), normalizedAnalysisLimit(req.Limit)),
				"cached":   true,
			})
			return
		}
	}

	sendSSEEvent(w, flusher, "progress", map[string]any{"phase": "analyzing"})
	result, err := nasanalyzer.NewAnalyzer().AnalyzeFileStream(r.Context(), job.MergedPcap, normalizedStreamBatchRows(req.BatchRows), func(progress analysisstream.Progress, result *nasanalyzer.AnalysisResult) error {
		result.Filename = displayPcapFilename(job.OriginalFiles, job.MergedPcap)
		event := "partial_result"
		if progress.Done {
			event = "done"
		}
		sendSSEEvent(w, flusher, event, map[string]any{
			"progress": progress,
			"result":   windowNASAnalysis(filter(result), normalizedAnalysisLimit(req.Limit)),
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
