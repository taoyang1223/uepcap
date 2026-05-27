package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

const (
	maxUploadBytes  int64 = 2 << 30 // 2 GiB total request body
	maxUploadMemory int64 = 8 << 20 // 8 MiB form field buffer; files are streamed to disk
)

// CreateJob handles POST /api/jobs - upload pcap files and create a job
func (h *Handler) CreateJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	reader, err := r.MultipartReader()
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to read multipart upload: %v", err))
		return
	}

	job, err := h.jobMgr.CreateJob()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create job: %v", err))
		return
	}

	jobDir := h.jobMgr.GetJobDir(job.ID)
	var savedFiles []string
	var fileCount int

	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			h.jobMgr.DeleteJob(job.ID)
			if isMaxBytesError(err) {
				writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("upload is too large; maximum total size is %s", formatBytes(maxUploadBytes)))
				return
			}
			writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to read uploaded file: %v", err))
			return
		}
		defer part.Close()

		if part.FormName() != "files" || part.FileName() == "" {
			if _, err := io.Copy(io.Discard, io.LimitReader(part, maxUploadMemory)); err != nil {
				h.jobMgr.DeleteJob(job.ID)
				writeError(w, http.StatusBadRequest, fmt.Sprintf("failed to discard form field: %v", err))
				return
			}
			continue
		}

		filename, err := safeUploadFilename(part.FileName())
		if err != nil {
			h.jobMgr.DeleteJob(job.ID)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		destPath := filepath.Join(jobDir, uniqueUploadFilename(savedFiles, filename))
		if err := saveUploadedPart(destPath, part); err != nil {
			h.jobMgr.DeleteJob(job.ID)
			if isMaxBytesError(err) {
				writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("upload is too large; maximum total size is %s", formatBytes(maxUploadBytes)))
				return
			}
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save file: %v", err))
			return
		}

		if info, err := os.Stat(destPath); err != nil {
			h.jobMgr.DeleteJob(job.ID)
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to inspect saved file: %v", err))
			return
		} else if info.Size() == 0 {
			h.jobMgr.DeleteJob(job.ID)
			writeError(w, http.StatusBadRequest, fmt.Sprintf("uploaded file %q is empty", filename))
			return
		}

		savedFiles = append(savedFiles, destPath)
		fileCount++
	}

	if len(savedFiles) == 0 {
		h.jobMgr.DeleteJob(job.ID)
		writeError(w, http.StatusBadRequest, "no files uploaded")
		return
	}

	// Merge pcap files if multiple, or just use the single file
	mergedPath := filepath.Join(jobDir, "merged.pcap")
	if len(savedFiles) > 1 {
		ctx, cancel := context.WithTimeout(context.Background(), mergeTimeoutForFiles(savedFiles))
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
		"file_count":  fileCount,
		"merged_pcap": mergedPath,
	})
}

func saveUploadedPart(destPath string, part *multipart.Part) error {
	destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	defer destFile.Close()
	_, err = io.CopyBuffer(destFile, part, make([]byte, 1024*1024))
	return err
}

func safeUploadFilename(filename string) (string, error) {
	base := filepath.Base(strings.TrimSpace(filename))
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", fmt.Errorf("invalid upload filename")
	}
	ext := strings.ToLower(filepath.Ext(base))
	if ext != ".pcap" && ext != ".pcapng" && ext != ".cap" && !strings.HasPrefix(ext, ".pcap") {
		return "", fmt.Errorf("unsupported file type %q; please upload .pcap, .pcap1, .pcapng or .cap files", ext)
	}
	return base, nil
}

func uniqueUploadFilename(existing []string, filename string) string {
	used := make(map[string]bool, len(existing))
	for _, path := range existing {
		used[filepath.Base(path)] = true
	}
	if !used[filename] {
		return filename
	}
	ext := filepath.Ext(filename)
	stem := strings.TrimSuffix(filename, ext)
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d%s", stem, i, ext)
		if !used[candidate] {
			return candidate
		}
	}
}

func mergeTimeoutForFiles(paths []string) time.Duration {
	var total int64
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil {
			total += info.Size()
		}
	}
	timeout := 2*time.Minute + time.Duration(total/(100<<20))*time.Minute
	if timeout > 30*time.Minute {
		return 30 * time.Minute
	}
	return timeout
}

func isMaxBytesError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

func formatBytes(bytes int64) string {
	if bytes >= 1<<30 {
		return fmt.Sprintf("%.1f GB", float64(bytes)/(1<<30))
	}
	return fmt.Sprintf("%.0f MB", float64(bytes)/(1<<20))
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
