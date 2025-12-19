package api

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"uepcap/internal/protocol"
	"uepcap/internal/tshark"
)

// ExportRequest represents export request body
type ExportRequest struct {
	IMSIs     []string `json:"imsis"`
	Protocols []string `json:"protocols"` // ngap, pfcp, s1ap, gtpv2, gtpu
}

// ExportPackets handles POST /api/jobs/{id}/export
// This is now an async operation: returns immediately with filter, pcap generation happens in background
func (h *Handler) ExportPackets(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req ExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if len(req.IMSIs) == 0 {
		writeError(w, http.StatusBadRequest, "no IMSIs specified")
		return
	}

	if len(req.Protocols) == 0 {
		// Default to all protocols
		req.Protocols = []string{"ngap", "pfcp", "s1ap", "gtpv2", "gtpu"}
	}

	// Generate cache key
	cacheKey := generateCacheKey(req.IMSIs, req.Protocols)

	// Check cache - if already exported, return immediately
	if cachedPath, ok := h.jobMgr.GetCachedExport(id, cacheKey); ok {
		if _, err := os.Stat(cachedPath); err == nil {
			filename := filepath.Base(cachedPath)
			writeSuccess(w, map[string]interface{}{
				"download_url": fmt.Sprintf("/api/jobs/%s/download/%s", id, filename),
				"filename":     filename,
				"cached":       true,
				"status":       "completed",
			})
			return
		}
	}

	jobDir := h.jobMgr.GetJobDir(id)
	exportDir := filepath.Join(jobDir, "exports")
	os.MkdirAll(exportDir, 0755)

	startTime := time.Now()
	log.Printf("[Export] Starting filter resolution for job %s: %d IMSIs, %d protocols", id, len(req.IMSIs), len(req.Protocols))

	// Phase 1: Quickly resolve all filters (this is the fast part)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	type filterResult struct {
		imsi   string
		filter string
		err    error
	}

	filterChan := make(chan filterResult, len(req.IMSIs))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4) // Max 4 concurrent filter resolutions

	for _, imsi := range req.IMSIs {
		wg.Add(1)
		go func(imsi string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resolver := protocol.NewFilterResolver()
			filter, err := resolver.ResolveFilter(ctx, job.MergedPcap, imsi, req.Protocols)
			filterChan <- filterResult{imsi: imsi, filter: filter, err: err}
		}(imsi)
	}

	go func() {
		wg.Wait()
		close(filterChan)
	}()

	// Collect filter results
	var filters []string
	imsiFilters := make(map[string]string) // imsi -> filter
	var firstError error

	for result := range filterChan {
		if result.err != nil && firstError == nil {
			firstError = fmt.Errorf("failed to resolve filter for IMSI %s: %v", result.imsi, result.err)
			continue
		}
		if result.filter != "" {
			filters = append(filters, result.filter)
			imsiFilters[result.imsi] = result.filter
		}
	}

	log.Printf("[Export] Filter resolution completed in %v, found %d valid filters", time.Since(startTime), len(filters))

	// If no filters found, return error
	if len(filters) == 0 {
		if firstError != nil {
			writeError(w, http.StatusInternalServerError, firstError.Error())
		} else {
			writeError(w, http.StatusNotFound, "no packets found for specified IMSIs")
		}
		return
	}

	// Combine all filters into one display filter
	var combinedFilter string
	if len(filters) == 1 {
		combinedFilter = filters[0]
	} else {
		wrappedFilters := make([]string, len(filters))
		for i, f := range filters {
			wrappedFilters[i] = "(" + f + ")"
		}
		combinedFilter = strings.Join(wrappedFilters, " || ")
	}

	// Create async export task
	task, err := h.jobMgr.CreateExportTask(id, len(imsiFilters), combinedFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create export task")
		return
	}

	// Return immediately with filter - user can copy to Wireshark right away
	writeSuccess(w, map[string]interface{}{
		"task_id":    task.ID,
		"status":     "processing",
		"filter":     combinedFilter,
		"imsi_count": len(imsiFilters),
	})

	// Phase 2: Start async pcap export in background
	go h.runAsyncExport(id, task.ID, cacheKey, job.MergedPcap, exportDir, imsiFilters)
}

// runAsyncExport performs pcap export in background
func (h *Handler) runAsyncExport(jobID, taskID, cacheKey, mergedPcap, exportDir string, imsiFilters map[string]string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	startTime := time.Now()
	log.Printf("[Export] Starting async pcap export for task %s: %d IMSIs", taskID, len(imsiFilters))

	h.jobMgr.UpdateExportTaskStatus(jobID, taskID, "processing", nil)

	type exportResult struct {
		imsi       string
		outputFile string
		err        error
	}

	resultChan := make(chan exportResult, len(imsiFilters))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)

	for imsi, filter := range imsiFilters {
		wg.Add(1)
		go func(imsi, filter string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			outputFile := filepath.Join(exportDir, fmt.Sprintf("ue_%s.pcap", imsi))
			if err := tshark.TsharkExport(ctx, mergedPcap, outputFile, filter); err != nil {
				log.Printf("[Export] IMSI %s export error: %v", imsi, err)
				resultChan <- exportResult{imsi: imsi, err: err}
				return
			}
			resultChan <- exportResult{imsi: imsi, outputFile: outputFile}
		}(imsi, filter)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var exportedFiles []string
	var firstError error
	for result := range resultChan {
		if result.err != nil && firstError == nil {
			firstError = result.err
		}
		if result.outputFile != "" {
			exportedFiles = append(exportedFiles, result.outputFile)
		}
	}

	log.Printf("[Export] Async export completed in %v, %d files exported", time.Since(startTime), len(exportedFiles))

	// Handle results
	if len(exportedFiles) == 0 {
		h.jobMgr.UpdateExportTaskStatus(jobID, taskID, "error", fmt.Errorf("no files exported"))
		return
	}

	var finalFile, filename string
	if len(exportedFiles) == 1 {
		finalFile = exportedFiles[0]
		filename = filepath.Base(finalFile)
	} else {
		zipFile := filepath.Join(exportDir, fmt.Sprintf("ue_export_%s.zip", cacheKey[:8]))
		if err := createZip(zipFile, exportedFiles); err != nil {
			h.jobMgr.UpdateExportTaskStatus(jobID, taskID, "error", err)
			return
		}
		finalFile = zipFile
		filename = filepath.Base(zipFile)
	}

	// Cache the export
	h.jobMgr.CacheExport(jobID, cacheKey, finalFile)

	// Mark task as completed
	downloadURL := fmt.Sprintf("/api/jobs/%s/download/%s", jobID, filename)
	h.jobMgr.CompleteExportTask(jobID, taskID, downloadURL, filename, len(exportedFiles))
	log.Printf("[Export] Task %s completed: %s", taskID, downloadURL)
}

// GetExportStatus handles GET /api/jobs/{id}/export/{taskId}/status
func (h *Handler) GetExportStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	taskID := r.PathValue("taskId")

	task, ok := h.jobMgr.GetExportTask(jobID, taskID)
	if !ok {
		writeError(w, http.StatusNotFound, "export task not found")
		return
	}

	writeSuccess(w, task.GetInfo())
}

// DownloadExport handles GET /api/jobs/{id}/download/{filename}
func (h *Handler) DownloadExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	filename := r.PathValue("filename")

	if _, ok := h.jobMgr.GetJob(id); !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	// Security: prevent path traversal
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	jobDir := h.jobMgr.GetJobDir(id)
	filePath := filepath.Join(jobDir, "exports", filename)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	if strings.HasSuffix(filename, ".zip") {
		w.Header().Set("Content-Type", "application/zip")
	} else {
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	}

	http.ServeFile(w, r, filePath)
}

func generateCacheKey(imsis, protocols []string) string {
	// Sort for consistent key
	sortedIMSIs := make([]string, len(imsis))
	copy(sortedIMSIs, imsis)
	sort.Strings(sortedIMSIs)

	sortedProtocols := make([]string, len(protocols))
	copy(sortedProtocols, protocols)
	sort.Strings(sortedProtocols)

	data := strings.Join(sortedIMSIs, ",") + "|" + strings.Join(sortedProtocols, ",")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func createZip(zipPath string, files []string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, file := range files {
		if err := addFileToZip(zipWriter, file); err != nil {
			return err
		}
	}

	return nil
}

func addFileToZip(zipWriter *zip.Writer, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(filePath)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}

// truncateFilter truncates a filter string for logging
func truncateFilter(filter string) string {
	if len(filter) > 100 {
		return filter[:100] + "..."
	}
	return filter
}
