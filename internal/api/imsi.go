package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"uepcap/internal/protocol"
)

// GetIMSIList handles GET /api/jobs/{id}/imsis - scan and return IMSI list (legacy)
func (h *Handler) GetIMSIList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	log.Printf("[IMSI] GetIMSIList called for job: %s", id)

	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		log.Printf("[IMSI] Job not found: %s", id)
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	log.Printf("[IMSI] Job found, MergedPcap: %s", job.MergedPcap)

	// Check if already scanned
	if imsiList, ok := h.jobMgr.GetJobIMSIList(id); ok {
		log.Printf("[IMSI] Returning cached IMSI list: %d items", len(imsiList))
		writeSuccess(w, map[string]interface{}{
			"imsis":  imsiList,
			"cached": true,
		})
		return
	}

	// Update status to scanning
	h.jobMgr.UpdateJobStatus(id, "scanning", nil)
	log.Printf("[IMSI] Starting IMSI scan for job: %s", id)

	// Scan IMSI list from merged pcap
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner := protocol.NewIMSIScanner()
	imsiList, err := scanner.ScanIMSIs(ctx, job.MergedPcap)
	if err != nil {
		log.Printf("[IMSI] Scan failed for job %s: %v", id, err)
		h.jobMgr.UpdateJobStatus(id, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	log.Printf("[IMSI] Scan completed for job %s: found %d IMSIs", id, len(imsiList))

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
	log.Printf("[IMSI-Stream] StreamIMSIList called for job: %s", id)

	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		log.Printf("[IMSI-Stream] Job not found: %s", id)
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	log.Printf("[IMSI-Stream] Job found, MergedPcap: %s", job.MergedPcap)

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		log.Printf("[IMSI-Stream] Streaming not supported for job: %s", id)
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	// Check if already scanned - send cached results immediately
	if imsiList, ok := h.jobMgr.GetJobIMSIList(id); ok {
		log.Printf("[IMSI-Stream] Returning cached IMSI list: %d items", len(imsiList))
		for _, imsi := range imsiList {
			sendSSEEvent(w, flusher, "imsi", imsi)
		}
		sendSSEEvent(w, flusher, "done", "cached")
		return
	}

	// Update status to scanning
	h.jobMgr.UpdateJobStatus(id, "scanning", nil)
	log.Printf("[IMSI-Stream] Starting IMSI stream scan for job: %s", id)

	// Create channel for streaming results
	imsiChan := make(chan string, 100)
	doneChan := make(chan error, 1)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	// Start scanning in background
	go func() {
		log.Printf("[IMSI-Stream] Background scan goroutine started for job: %s", id)
		scanner := protocol.NewIMSIScanner()
		err := scanner.ScanIMSIsStream(ctx, job.MergedPcap, imsiChan)
		log.Printf("[IMSI-Stream] Background scan completed for job %s, error: %v", id, err)
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
			log.Printf("[IMSI-Stream] Found IMSI: %s (total: %d)", imsi, len(allIMSIs))
			sendSSEEvent(w, flusher, "imsi", imsi)

		case err := <-doneChan:
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
			log.Printf("[IMSI-Stream] Context timeout for job: %s", id)
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
