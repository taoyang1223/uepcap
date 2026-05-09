package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/protocol"
	"gitee.com/yangdadayyds/uepcap/internal/statistics"
)

// MessageStatsRequest represents a message statistics request body.
type MessageStatsRequest struct {
	IMSIs []string `json:"imsis"`
}

// GetMessageStats handles POST /api/jobs/{id}/message-stats.
func (h *Handler) GetMessageStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req MessageStatsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	scopeFilter, err := resolveMessageStatsScope(ctx, job.MergedPcap, req.IMSIs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	result, err := statistics.Count(ctx, job.MergedPcap, scopeFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeSuccess(w, result)
}

func resolveMessageStatsScope(ctx context.Context, pcapFile string, imsis []string) (string, error) {
	if len(imsis) == 0 {
		return "", nil
	}

	resolver := protocol.NewFilterResolver()
	protocols := []string{"ngap", "pfcp", "gtpv2"}
	filters := make([]string, 0, len(imsis))
	var firstError error

	for _, imsi := range imsis {
		imsi = strings.TrimSpace(imsi)
		if imsi == "" {
			continue
		}

		filter, err := resolver.ResolveFilter(ctx, pcapFile, imsi, protocols)
		if err != nil {
			if firstError == nil {
				firstError = fmt.Errorf("failed to resolve statistics filter for IMSI %s: %w", imsi, err)
			}
			continue
		}
		if filter != "" {
			filters = append(filters, "("+filter+")")
		}
	}

	if len(filters) == 0 {
		if firstError != nil {
			return "", firstError
		}
		return "", fmt.Errorf("no packets found for specified IMSIs")
	}

	return strings.Join(filters, " || "), nil
}
