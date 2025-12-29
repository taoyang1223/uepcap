package job

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	ID              string                 `json:"id"`
	CreatedAt       time.Time              `json:"created_at"`
	MergedPcap      string                 `json:"merged_pcap"`
	OriginalFiles   []string               `json:"original_files"`
	IMSIList        []string               `json:"imsi_list,omitempty"`
	IMSIScanned     bool                   `json:"imsi_scanned"`
	Status          string                 `json:"status"` // created, scanning, ready, exporting, error
	Error           string                 `json:"error,omitempty"`
	ExportCache     map[string]string      `json:"-"` // key: imsi+protocols hash, value: exported pcap path
	TextExportCache map[string]string      `json:"-"` // key: filter hash, value: compact JSON text
	TreeCache       map[string]string      `json:"-"` // key: proto|frame, value: protocol tree text
	TreePrefetched  map[string]bool        `json:"-"` // key: filterHash, tracks which filters have been prefetched
	ExportTasks     map[string]*ExportTask `json:"-"` // key: task_id
	mu              sync.RWMutex
}

// Manager manages job lifecycle and storage
type Manager struct {
	dataDir string
	ttl     time.Duration
	maxJobs int // Maximum number of jobs to keep (0 = unlimited)
	jobs    map[string]*Job
	mu      sync.RWMutex
}

// NewManager creates a new job manager
func NewManager(dataDir string, ttl time.Duration) *Manager {
	return NewManagerWithLimit(dataDir, ttl, 3) // Default: keep max 3 jobs
}

// NewManagerWithLimit creates a new job manager with custom job limit
func NewManagerWithLimit(dataDir string, ttl time.Duration, maxJobs int) *Manager {
	// Ensure data directory exists
	tmpDir := filepath.Join(dataDir, "tmp")
	os.MkdirAll(tmpDir, 0755)

	return &Manager{
		dataDir: dataDir,
		ttl:     ttl,
		maxJobs: maxJobs,
		jobs:    make(map[string]*Job),
	}
}

// CreateJob creates a new job
func (m *Manager) CreateJob() (*Job, error) {
	// Clean up old jobs if we've reached the limit
	m.cleanupOldJobs()

	id := uuid.New().String()
	jobDir := filepath.Join(m.dataDir, "tmp", id)
	if err := os.MkdirAll(jobDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create job directory: %w", err)
	}

	job := &Job{
		ID:              id,
		CreatedAt:       time.Now(),
		Status:          "created",
		ExportCache:     make(map[string]string),
		TextExportCache: make(map[string]string),
		TreeCache:       make(map[string]string),
		TreePrefetched:  make(map[string]bool),
		ExportTasks:     make(map[string]*ExportTask),
	}

	m.mu.Lock()
	m.jobs[id] = job
	m.mu.Unlock()

	return job, nil
}

// cleanupOldJobs removes the oldest jobs when exceeding maxJobs limit
func (m *Manager) cleanupOldJobs() {
	if m.maxJobs <= 0 {
		return // No limit
	}

	m.mu.RLock()
	jobCount := len(m.jobs)
	if jobCount < m.maxJobs {
		m.mu.RUnlock()
		return
	}

	// Collect jobs and sort by creation time
	jobs := make([]*Job, 0, len(m.jobs))
	for _, job := range m.jobs {
		jobs = append(jobs, job)
	}
	m.mu.RUnlock()

	// Sort by CreatedAt (oldest first)
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].CreatedAt.Before(jobs[j].CreatedAt)
	})

	// Calculate how many jobs to delete (keep maxJobs - 1 to make room for the new one)
	deleteCount := jobCount - m.maxJobs + 1
	if deleteCount <= 0 {
		return
	}

	// Delete the oldest jobs
	for i := 0; i < deleteCount && i < len(jobs); i++ {
		jobID := jobs[i].ID
		fmt.Printf("[JobManager] Auto-cleaning old job: %s (created: %s)\n", jobID, jobs[i].CreatedAt.Format(time.RFC3339))
		m.DeleteJob(jobID)
	}
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

// CacheTextExport caches a text export result
func (m *Manager) CacheTextExport(jobID, cacheKey, text string) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.Lock()
	job.TextExportCache[cacheKey] = text
	job.mu.Unlock()
}

// GetCachedTextExport gets a cached text export
func (m *Manager) GetCachedTextExport(jobID, cacheKey string) (string, bool) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return "", false
	}

	job.mu.RLock()
	defer job.mu.RUnlock()
	text, ok := job.TextExportCache[cacheKey]
	return text, ok
}

// TreeCacheKey generates a cache key for protocol tree
func TreeCacheKey(protocol string, frameNumber int) string {
	return fmt.Sprintf("%s|%d", protocol, frameNumber)
}

// CacheProtocolTree caches a protocol tree result
func (m *Manager) CacheProtocolTree(jobID, cacheKey, tree string) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	job.mu.Lock()
	if job.TreeCache == nil {
		job.TreeCache = make(map[string]string)
	}
	job.TreeCache[cacheKey] = tree
	job.mu.Unlock()
}

// GetCachedProtocolTree gets a cached protocol tree
func (m *Manager) GetCachedProtocolTree(jobID, cacheKey string) (string, bool) {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return "", false
	}

	job.mu.RLock()
	defer job.mu.RUnlock()
	if job.TreeCache == nil {
		return "", false
	}
	tree, ok := job.TreeCache[cacheKey]
	return tree, ok
}

// MarkTreePrefetched marks a filter as prefetched (returns true if already marked)
func (m *Manager) MarkTreePrefetched(jobID, filterHash string) bool {
	m.mu.RLock()
	job, ok := m.jobs[jobID]
	m.mu.RUnlock()
	if !ok {
		return true // Treat missing job as "already prefetched" to skip
	}

	job.mu.Lock()
	defer job.mu.Unlock()
	if job.TreePrefetched == nil {
		job.TreePrefetched = make(map[string]bool)
	}
	if job.TreePrefetched[filterHash] {
		return true // Already prefetched
	}
	job.TreePrefetched[filterHash] = true
	return false
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

// GetMu returns the job's mutex for external locking
func (j *Job) GetMu() *sync.RWMutex {
	return &j.mu
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
