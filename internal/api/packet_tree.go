package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/job"
	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

// GetPacketTreeRequest represents the query parameters for packet tree API
type GetPacketTreeRequest struct {
	Protocol string `json:"protocol"`
}

// GetPacketTreeResponse represents the response for packet tree API
type GetPacketTreeResponse struct {
	Frame    int    `json:"frame"`
	Protocol string `json:"protocol"`
	Tree     string `json:"tree"`
	Cached   bool   `json:"cached"`
}

// GetPacketTree handles GET /api/jobs/{id}/packets/{frame}/tree?proto=...
// It returns the protocol tree text for a specific frame and protocol
func (h *Handler) GetPacketTree(w http.ResponseWriter, r *http.Request) {
	// Extract job ID from path
	jobID := r.PathValue("id")
	if jobID == "" {
		writeError(w, http.StatusBadRequest, "missing job id")
		return
	}

	// Extract frame number from path
	frameStr := r.PathValue("frame")
	if frameStr == "" {
		writeError(w, http.StatusBadRequest, "missing frame number")
		return
	}

	frameNumber, err := strconv.Atoi(frameStr)
	if err != nil || frameNumber <= 0 {
		writeError(w, http.StatusBadRequest, "invalid frame number: must be a positive integer")
		return
	}

	// Extract protocol from query parameter
	protocol := r.URL.Query().Get("proto")
	if protocol == "" {
		writeError(w, http.StatusBadRequest, "missing proto parameter")
		return
	}

	// Normalize and validate protocol
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if !tshark.IsAllowedProtocol(protocol) {
		allowedList := strings.Join(tshark.GetAllowedProtocols(), ", ")
		writeError(w, http.StatusBadRequest, fmt.Sprintf(
			"protocol %q is not allowed. Allowed protocols: %s", protocol, allowedList))
		return
	}

	// Get job
	j, ok := h.jobMgr.GetJob(jobID)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	// Check job has merged pcap
	j.GetMu().RLock()
	pcapPath := j.MergedPcap
	j.GetMu().RUnlock()

	if pcapPath == "" {
		writeError(w, http.StatusBadRequest, "job has no pcap file")
		return
	}

	// Check cache first
	cacheKey := job.TreeCacheKey(protocol, frameNumber)
	if cachedTree, found := h.jobMgr.GetCachedProtocolTree(jobID, cacheKey); found {
		writeSuccess(w, GetPacketTreeResponse{
			Frame:    frameNumber,
			Protocol: protocol,
			Tree:     cachedTree,
			Cached:   true,
		})
		return
	}

	// Run tshark with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result, err := tshark.TsharkProtocolTree(ctx, pcapPath, frameNumber, protocol)
	if err != nil {
		// Check if it's a context timeout
		if ctx.Err() == context.DeadlineExceeded {
			writeError(w, http.StatusGatewayTimeout, "tshark execution timed out")
			return
		}
		// Check if frame/protocol not found - normalize various "not found" patterns to 404
		errStr := err.Error()
		if strings.Contains(errStr, "not found") ||
			strings.Contains(errStr, "tree not found") ||
			strings.Contains(errStr, "no packet found") {
			writeError(w, http.StatusNotFound, errStr)
			return
		}
		writeError(w, http.StatusInternalServerError, errStr)
		return
	}

	// Cache the result
	h.jobMgr.CacheProtocolTree(jobID, cacheKey, result.Tree)

	writeSuccess(w, GetPacketTreeResponse{
		Frame:    result.Frame,
		Protocol: result.Protocol,
		Tree:     result.Tree,
		Cached:   false,
	})
}

