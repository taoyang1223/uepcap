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

	result, err := ngapanalyzer.NewAnalyzer().AnalyzeFile(ctx, job.MergedPcap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result.Filename = displayPcapFilename(job.OriginalFiles, job.MergedPcap)

	writeSuccess(w, result)
}
