package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/nasanalyzer"
)

type NASMessagesRequest struct {
	Limit int `json:"limit,omitempty"`
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
		result, err := nasanalyzer.NewAnalyzer().AnalyzeFile(ctx, job.MergedPcap)
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
