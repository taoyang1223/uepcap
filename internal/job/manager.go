package job

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ExportTask represents an async export task
type ExportTask struct {
	ID          string    `json:"id"`
	JobID       string    `json:"job_id"`
	Status      string    `json:"status"` // pending, processing, completed, error
	Filter      string    `json:"filter,omitempty"`
	DownloadURL string    `json:"download_url,omitempty"`
	Filename    string    `json:"filename,omitempty"`
	IMSICount   int       `json:"imsi_count"`
	FileCount   int       `json:"file_count,omitempty"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
	mu          sync.RWMutex
}

// Job represents a pcap processing job
type Job struct {
	ID            string                 `json:"id"`
	CreatedAt     time.Time              `json:"created_at"`
	MergedPcap    string                 `json:"merged_pcap"`
	OriginalFiles []string               `json:"original_files"`
	IMSIList      []string               `json:"imsi_list,omitempty"`
	IMSIScanned   bool                   `json:"imsi_scanned"`
	Status        string                 `json:"status"` // created, scanning, ready, exporting, error
	Error         string                 `json:"error,omitempty"`
	ExportCache   map[string]string      `json:"-"` // key: imsi+protocols hash, value: exported pcap path
	ExportTasks   map[string]*ExportTask `json:"-"` // key: task_id
	mu            sync.RWMutex
}

// Manager manages job lifecycle and storage
type Manager struct {
	dataDir string
	ttl     time.Duration
	jobs    map[string]*Job
	mu      sync.RWMutex
}

// NewManager creates a new job manager
func NewManager(dataDir string, ttl time.Duration) *Manager {
	// Ensure data directory exists
	tmpDir := filepath.Join(dataDir, "tmp")
	os.MkdirAll(tmpDir, 0755)

	return &Manager{
		dataDir: dataDir,
		ttl:     ttl,
		jobs:    make(map[string]*Job),
	}
}

// CreateJob creates a new job
func (m *Manager) CreateJob() (*Job, error) {
	id := uuid.New().String()
	jobDir := filepath.Join(m.dataDir, "tmp", id)
	if err := os.MkdirAll(jobDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create job directory: %w", err)
	}

	job := &Job{
		ID:          id,
		CreatedAt:   time.Now(),
		Status:      "created",
		ExportCache: make(map[string]string),
		ExportTasks: make(map[string]*ExportTask),
	}

	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()

	return job, nil
}

// GetJob returns a job by ID
func (m *Manager) GetJob(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	job, ok := m.jobs[id]
	return job, ok
}

// GetJobDir returns the job's directory path
func (m *Manager) GetJobDir(id string) string {
	return filepath.Join(m.dataDir, "tmp", id)
}

// DeleteJob removes a job and its files
func (m *Manager) DeleteJob(id string) error {
	m.mu.Lock()
	delete(m.jobs, id)
	m.mu.Unlock()

	jobDir := m.GetJobDir(id)
	return os.RemoveAll(jobDir)
}

// ListJobs returns all jobs
func (m *Manager) ListJobs() []*Job {
	m.mu.RLock()
	defer m.mu.RUnlock()

	jobs := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	return jobs
}

// UpdateJobStatus updates job status
func (m *Manager) UpdateJobStatus(id, status string, err error) {
	m.mu.RLock()
	job, ok := m.jobs[id]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.Lock()
	job.Status = status
	if err != nil {
		job.Error = err.Error()
	}
	job.mu.Unlock()
}

// SetJobMergedPcap sets the merged pcap path
func (m *Manager) SetJobMergedPcap(id, pcapPath string, originalFiles []string) {
	m.mu.RLock()
	job, ok := m.jobs[id]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.Lock()
	job.MergedPcap = pcapPath
	job.OriginalFiles = originalFiles
	job.mu.Unlock()
}

// SetJobIMSIList sets the scanned IMSI list
func (m *Manager) SetJobIMSIList(id string, imsiList []string) {
	m.mu.RLock()
	job, ok := m.jobs[id]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.Lock()
	job.IMSIList = imsiList
	job.IMSIScanned = true
	job.mu.Unlock()
}

// GetJobIMSIList returns the IMSI list
func (m *Manager) GetJobIMSIList(id string) ([]string, bool) {
	m.mu.RLock()
	job, ok := m.jobs[id]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}

	job.mu.RLock()
	defer job.mu.RUnlock()
	if !job.IMSIScanned {
		return nil, false
	}
	return job.IMSIList, true
}

// CacheExport caches an export result
func (m *Manager) CacheExport(jobID, cacheKey, exportPath string) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.Lock()
	job.ExportCache[cacheKey] = exportPath
	job.mu.Unlock()
}

// GetCachedExport gets a cached export path
func (m *Manager) GetCachedExport(jobID, cacheKey string) (string, bool) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return "", false
	}

	job.mu.RLock()
	defer job.mu.RUnlock()
	path, ok := job.ExportCache[cacheKey]
	return path, ok
}

// CreateExportTask creates a new export task
func (m *Manager) CreateExportTask(jobID string, imsiCount int, filter string) (*ExportTask, error) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("job not found")
	}

	taskID := uuid.New().String()[:8]
	task := &ExportTask{
		ID:        taskID,
		JobID:     jobID,
		Status:    "pending",
		Filter:    filter,
		IMSICount: imsiCount,
		CreatedAt: time.Now(),
	}

	job.mu.Lock()
	job.ExportTasks[taskID] = task
	job.mu.Unlock()

	return task, nil
}

// GetExportTask gets an export task by ID
func (m *Manager) GetExportTask(jobID, taskID string) (*ExportTask, bool) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}

	job.mu.RLock()
	defer job.mu.RUnlock()
	task, ok := job.ExportTasks[taskID]
	return task, ok
}

// UpdateExportTaskStatus updates export task status
func (m *Manager) UpdateExportTaskStatus(jobID, taskID, status string, err error) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.RLock()
	task, ok := job.ExportTasks[taskID]
	job.mu.RUnlock()
	if !ok {
		return
	}

	task.mu.Lock()
	task.Status = status
	if err != nil {
		task.Error = err.Error()
	}
	task.mu.Unlock()
}

// CompleteExportTask marks an export task as completed
func (m *Manager) CompleteExportTask(jobID, taskID, downloadURL, filename string, fileCount int) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.RLock()
	task, ok := job.ExportTasks[taskID]
	job.mu.RUnlock()
	if !ok {
		return
	}

	task.mu.Lock()
	task.Status = "completed"
	task.DownloadURL = downloadURL
	task.Filename = filename
	task.FileCount = fileCount
	task.CompletedAt = time.Now()
	task.mu.Unlock()
}

// GetExportTaskInfo returns task info for API response
func (t *ExportTask) GetInfo() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	info := map[string]interface{}{
		"task_id":    t.ID,
		"status":     t.Status,
		"filter":     t.Filter,
		"imsi_count": t.IMSICount,
		"created_at": t.CreatedAt,
	}

	if t.DownloadURL != "" {
		info["download_url"] = t.DownloadURL
		info["filename"] = t.Filename
		info["file_count"] = t.FileCount
	}
	if t.Error != "" {
		info["error"] = t.Error
	}
	if !t.CompletedAt.IsZero() {
		info["completed_at"] = t.CompletedAt
	}

	return info
}

// StartCleanup starts the TTL cleanup goroutine
func (m *Manager) StartCleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

func (m *Manager) cleanup() {
	now := time.Now()
	var expired []string

	m.mu.RLock()
	for id, job := range m.jobs {
		if now.Sub(job.CreatedAt) > m.ttl {
			expired = append(expired, id)
		}
	}
	m.mu.RUnlock()

	for _, id := range expired {
		m.DeleteJob(id)
	}
}
