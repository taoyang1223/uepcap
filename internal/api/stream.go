package api

import (
	"net/http"
)

const defaultStreamBatchRows = 5000

func prepareEventStream(w http.ResponseWriter) (http.Flusher, bool) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	return flusher, ok
}

func normalizedStreamBatchRows(value int) int {
	if value <= 0 {
		return defaultStreamBatchRows
	}
	if value > 50000 {
		return 50000
	}
	return value
}
