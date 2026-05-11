package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/protocol"
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	imsiList, shared, err := h.scanIMSIsOnce(ctx, id, job.MergedPcap)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeSuccess(w, map[string]interface{}{
		"imsis":  imsiList,
		"cached": shared,
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
		sendSSEEvent(w, flusher, "imsis", imsiList)
		sendSSEEvent(w, flusher, "done", "cached")
		return
	}

	if call, ok := h.activeIMSIScan(id); ok {
		select {
		case <-call.done:
			if call.err != nil {
				sendSSEEvent(w, flusher, "error", call.err.Error())
				return
			}
			sendSSEEvent(w, flusher, "imsis", call.imsis)
			sendSSEEvent(w, flusher, "done", fmt.Sprintf("shared:%d", len(call.imsis)))
			return
		case <-r.Context().Done():
			return
		}
	}

	// Update status to scanning
	h.jobMgr.UpdateJobStatus(id, "scanning", nil)

	call := h.beginIMSIScan(id)
	if call == nil {
		sendSSEEvent(w, flusher, "error", "scan already running")
		return
	}
	defer h.finishIMSIScan(id, call)

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
			call.imsis = allIMSIs
			call.err = err
			if err != nil {
				log.Printf("[IMSI-Stream] Scan error for job %s: %v", id, err)
				h.jobMgr.UpdateJobStatus(id, "error", err)
				sendSSEEvent(w, flusher, "error", err.Error())
			} else {
				log.Printf("[IMSI-Stream] Scan completed for job %s: found %d IMSIs", id, len(allIMSIs))
				// Cache results
				h.jobMgr.SetJobIMSIList(id, allIMSIs)
				h.jobMgr.UpdateJobStatus(id, "ready", nil)
				sendSSEEvent(w, flusher, "done", fmt.Sprintf("total:%d", len(allIMSIs)))
			}
			return

		case <-ctx.Done():
			call.err = ctx.Err()
			sendSSEEvent(w, flusher, "error", "timeout")
			return
		}
	}
}

// sendSSEEvent sends a Server-Sent Event
func sendSSEEvent(w http.ResponseWriter, flusher http.Flusher, event string, data any) {
	fmt.Fprintf(w, "event: %s\n", event)
	jsonData, _ := json.Marshal(data)
	fmt.Fprintf(w, "data: %s\n\n", jsonData)
	flusher.Flush()
}

func (h *Handler) scanIMSIsOnce(ctx context.Context, jobID, pcapFile string) ([]string, bool, error) {
	if imsis, ok := h.jobMgr.GetJobIMSIList(jobID); ok {
		return imsis, true, nil
	}

	call := h.beginIMSIScan(jobID)
	if call == nil {
		existing, ok := h.activeIMSIScan(jobID)
		if !ok {
			return nil, false, fmt.Errorf("IMSI scan state changed")
		}
		select {
		case <-existing.done:
			return existing.imsis, true, existing.err
		case <-ctx.Done():
			return nil, true, ctx.Err()
		}
	}
	defer h.finishIMSIScan(jobID, call)

	h.jobMgr.UpdateJobStatus(jobID, "scanning", nil)
	scanner := protocol.NewIMSIScanner()
	imsis, err := scanner.ScanIMSIs(ctx, pcapFile)
	call.imsis = imsis
	call.err = err
	if err != nil {
		h.jobMgr.UpdateJobStatus(jobID, "error", err)
		return nil, false, err
	}
	h.jobMgr.SetJobIMSIList(jobID, imsis)
	h.jobMgr.UpdateJobStatus(jobID, "ready", nil)
	return imsis, false, nil
}

func (h *Handler) beginIMSIScan(jobID string) *imsiScanCall {
	h.imsiScanMu.Lock()
	defer h.imsiScanMu.Unlock()
	if h.imsiScans[jobID] != nil {
		return nil
	}
	call := &imsiScanCall{done: make(chan struct{})}
	h.imsiScans[jobID] = call
	return call
}

func (h *Handler) activeIMSIScan(jobID string) (*imsiScanCall, bool) {
	h.imsiScanMu.Lock()
	defer h.imsiScanMu.Unlock()
	call := h.imsiScans[jobID]
	return call, call != nil
}

func (h *Handler) finishIMSIScan(jobID string, call *imsiScanCall) {
	h.imsiScanMu.Lock()
	if h.imsiScans[jobID] == call {
		delete(h.imsiScans, jobID)
	}
	h.imsiScanMu.Unlock()
	close(call.done)
}
