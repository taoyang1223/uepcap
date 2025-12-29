package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

// CreateJob handles POST /api/jobs - upload pcap files and create a job
func (h *Handler) CreateJob(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (max 500MB)
	if err := r.ParseMultipartForm(500 << 20); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse form: %v", err))
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		writeError(w, http.StatusBadRequest, "no files uploaded")
		return
	}

	// Create job
	job, err := h.jobMgr.CreateJob()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create job: %v", err))
		return
	}

	jobDir := h.jobMgr.GetJobDir(job.ID)
	var savedFiles []string

	// Save uploaded files
	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to open uploaded file: %v", err))
			return
		}
		defer file.Close()

		// Save to job directory
		destPath := filepath.Join(jobDir, fileHeader.Filename)
		destFile, err := os.Create(destPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create file: %v", err))
			return
		}

		if _, err := io.Copy(destFile, file); err != nil {
			destFile.Close()
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save file: %v", err))
			return
		}
		destFile.Close()
		savedFiles = append(savedFiles, destPath)
	}

	// Merge pcap files if multiple, or just use the single file
	mergedPath := filepath.Join(jobDir, "merged.pcap")
	if len(savedFiles) > 1 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := tshark.Mergecap(ctx, mergedPath, savedFiles...); err != nil {
			h.jobMgr.UpdateJobStatus(job.ID, "error", err)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to merge pcap files: %v", err))
			return
		}
	} else {
		// Single file, just rename/copy
		if err := os.Rename(savedFiles[0], mergedPath); err != nil {
			// If rename fails (cross-device), try copy
			src, _ := os.Open(savedFiles[0])
			dst, _ := os.Create(mergedPath)
			io.Copy(dst, src)
			src.Close()
			dst.Close()
			os.Remove(savedFiles[0])
		}
	}

	h.jobMgr.SetJobMergedPcap(job.ID, mergedPath, savedFiles)
	h.jobMgr.UpdateJobStatus(job.ID, "ready", nil)

	writeSuccess(w, map[string]interface{}{
		"job_id":      job.ID,
		"file_count":  len(files),
		"merged_pcap": mergedPath,
	})
}

// ListJobs handles GET /api/jobs
func (h *Handler) ListJobs(w http.ResponseWriter, r *http.Request) {
	jobs := h.jobMgr.ListJobs()
	writeSuccess(w, jobs)
}

// GetJob handles GET /api/jobs/{id}
func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	writeSuccess(w, job)
}

// DeleteJob handles DELETE /api/jobs/{id}
func (h *Handler) DeleteJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := h.jobMgr.GetJob(id); !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if err := h.jobMgr.DeleteJob(id); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete job: %v", err))
		return
	}
	writeSuccess(w, map[string]string{"message": "job deleted"})
}
