package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/ngapanalyzer"
)

type NGAPMessagesRequest struct {
	Limit int `json:"limit,omitempty"`
}

func (h *Handler) GetNGAPMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req NGAPMessagesRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	value, err := h.analysis.getOrCompute(ctx, id+"|ngap", func(ctx context.Context) (any, error) {
		result, err := ngapanalyzer.NewAnalyzer().AnalyzeFile(ctx, job.MergedPcap)
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

	result, ok := value.(*ngapanalyzer.AnalysisResult)
	if !ok {
		writeError(w, http.StatusInternalServerError, "invalid NGAP analysis result")
		return
	}

	out := windowNGAPAnalysis(result, normalizedAnalysisLimit(req.Limit))
	writeSuccess(w, out)
}
