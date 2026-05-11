package api

import (
	"context"
	"net/http"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/ngapanalyzer"
)

func (h *Handler) GetNGAPMessages(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
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

	writeSuccess(w, value)
}
