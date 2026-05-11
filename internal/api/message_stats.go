package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/protocol"
	"gitee.com/yangdadayyds/uepcap/internal/statistics"
)

type messageStatsCacheStore struct {
	mu      sync.Mutex
	results map[string]*statistics.Result
	calls   map[string]*messageStatsCall
}

type messageStatsCall struct {
	done   chan struct{}
	result *statistics.Result
	err    error
}

func newMessageStatsCacheStore() *messageStatsCacheStore {
	return &messageStatsCacheStore{
		results: make(map[string]*statistics.Result),
		calls:   make(map[string]*messageStatsCall),
	}
}

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

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	result, err := h.messageStatsResult(ctx, id, job.MergedPcap, req.IMSIs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeSuccess(w, result)
}

func (h *Handler) messageStatsResult(ctx context.Context, jobID, pcapFile string, imsis []string) (*statistics.Result, error) {
	key := messageStatsCacheKey(jobID, imsis)

	h.messageStats.mu.Lock()
	if result, ok := h.messageStats.results[key]; ok {
		h.messageStats.mu.Unlock()
		return result, nil
	}
	if call, ok := h.messageStats.calls[key]; ok {
		h.messageStats.mu.Unlock()
		select {
		case <-call.done:
			return call.result, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	call := &messageStatsCall{done: make(chan struct{})}
	h.messageStats.calls[key] = call
	h.messageStats.mu.Unlock()

	call.result, call.err = countMessageStats(ctx, pcapFile, imsis)

	h.messageStats.mu.Lock()
	delete(h.messageStats.calls, key)
	if call.err == nil && call.result != nil {
		h.messageStats.results[key] = call.result
	}
	close(call.done)
	h.messageStats.mu.Unlock()

	return call.result, call.err
}

func countMessageStats(ctx context.Context, pcapFile string, imsis []string) (*statistics.Result, error) {
	scopeFilter, err := resolveMessageStatsScope(ctx, pcapFile, imsis)
	if err != nil {
		return nil, err
	}
	result, err := statistics.Count(ctx, pcapFile, scopeFilter)
	if err != nil {
		return nil, err
	}
	if len(imsis) > 0 {
		result.ScopeFilter = fmt.Sprintf("%d 个 UE", len(cleanIMSIs(imsis)))
	} else {
		result.ScopeFilter = "全量抓包"
	}
	return result, nil
}

func messageStatsCacheKey(jobID string, imsis []string) string {
	cleaned := cleanIMSIs(imsis)
	return jobID + "|" + strings.Join(cleaned, ",")
}

func cleanIMSIs(imsis []string) []string {
	cleaned := make([]string, 0, len(imsis))
	for _, imsi := range imsis {
		imsi = strings.TrimSpace(imsi)
		if imsi != "" {
			cleaned = append(cleaned, imsi)
		}
	}
	sort.Strings(cleaned)
	return cleaned
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
