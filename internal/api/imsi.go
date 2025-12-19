package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"uepcap/internal/protocol"
)

// GetIMSIList handles GET /api/jobs/{id}/imsis - scan and return IMSI list (legacy)
func (h *Handler) GetIMSIList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	// Check if already scanned
	if imsiList, ok := h.jobMgr.GetJobIMSIList(id); ok {
		writeSuccess(w, map[string]interface{}{
			"imsis":  imsiList,
			"cached": true,
		})
		return
	}

	// Update status to scanning
	h.jobMgr.UpdateJobStatus(id, "scanning", nil)

	// Scan IMSI list from merged pcap
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner := protocol.NewIMSIScanner()
	imsiList, err := scanner.ScanIMSIs(ctx, job.MergedPcap)
	if err != nil {
		h.jobMgr.UpdateJobStatus(id, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Cache results
	h.jobMgr.SetJobIMSIList(id, imsiList)
	h.jobMgr.UpdateJobStatus(id, "ready", nil)

	writeSuccess(w, map[string]interface{}{
		"imsis":  imsiList,
		"cached": false,
	})
}

// StreamIMSIList handles GET /api/jobs/{id}/imsis/stream - SSE stream for real-time IMSI updates
func (h *Handler) StreamIMSIList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Check if already scanned - send cached results immediately
	if imsiList, ok := h.jobMgr.GetJobIMSIList(id); ok {
		for _, imsi := range imsiList {
			sendSSEEvent(w, flusher, "imsi", imsi)
		}
		sendSSEEvent(w, flusher, "done", "cached")
		return
	}

	// Update status to scanning
	h.jobMgr.UpdateJobStatus(id, "scanning", nil)

	// Create channel for streaming results
	imsiChan := make(chan string, 100)
	doneChan := make(chan error, 1)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	// Start scanning in background
	go func() {
		scanner := protocol.NewIMSIScanner()
		err := scanner.ScanIMSIsStream(ctx, job.MergedPcap, imsiChan)
		doneChan <- err
	}()

	// Collect all IMSIs for caching
	var allIMSIs []string

	// Stream results as they come
	for {
		select {
		case imsi, ok := <-imsiChan:
			if !ok {
				// Channel closed, wait for done
				continue
			}
			allIMSIs = append(allIMSIs, imsi)
			sendSSEEvent(w, flusher, "imsi", imsi)

		case err := <-doneChan:
			if err != nil {
				h.jobMgr.UpdateJobStatus(id, "error", err)
				sendSSEEvent(w, flusher, "error", err.Error())
			} else {
				// Cache results
				h.jobMgr.SetJobIMSIList(id, allIMSIs)
				h.jobMgr.UpdateJobStatus(id, "ready", nil)
				sendSSEEvent(w, flusher, "done", fmt.Sprintf("total:%d", len(allIMSIs)))
			}
			return

		case <-ctx.Done():
			sendSSEEvent(w, flusher, "error", "timeout")
			return
		}
	}
}

// sendSSEEvent sends a Server-Sent Event
func sendSSEEvent(w http.ResponseWriter, flusher http.Flusher, event, data string) {
	fmt.Fprintf(w, "event: %s\n", event)
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
	flusher.Flush()
}
