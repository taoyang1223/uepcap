package job

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagerCreateJob(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "uepcap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 1*time.Hour)

	// Create job
	job, err := mgr.CreateJob()
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}

	if job.ID == "" {
		t.Error("job ID should not be empty")
	}

	if job.Status != "created" {
		t.Errorf("expected status 'created', got %q", job.Status)
	}

	// Verify job directory exists
	jobDir := mgr.GetJobDir(job.ID)
	if _, err := os.Stat(jobDir); os.IsNotExist(err) {
		t.Error("job directory should exist")
	}

	// Get job
	retrieved, ok := mgr.GetJob(job.ID)
	if !ok {
		t.Error("GetJob should return true")
	}
	if retrieved.ID != job.ID {
		t.Error("retrieved job ID should match")
	}

	// List jobs
	jobs := mgr.ListJobs()
	if len(jobs) != 1 {
		t.Errorf("expected 1 job, got %d", len(jobs))
	}
}

func TestManagerDeleteJob(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uepcap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 1*time.Hour)
	job, _ := mgr.CreateJob()
	jobDir := mgr.GetJobDir(job.ID)

	// Create a file in job dir
	testFile := filepath.Join(jobDir, "test.txt")
	os.WriteFile(testFile, []byte("test"), 0644)

	// Delete job
	if err := mgr.DeleteJob(job.ID); err != nil {
		t.Fatalf("DeleteJob failed: %v", err)
	}

	// Verify job is deleted
	if _, ok := mgr.GetJob(job.ID); ok {
		t.Error("job should be deleted")
	}

	// Verify directory is deleted
	if _, err := os.Stat(jobDir); !os.IsNotExist(err) {
		t.Error("job directory should be deleted")
	}
}

func TestManagerIMSIList(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uepcap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 1*time.Hour)
	job, _ := mgr.CreateJob()

	// Initially no IMSI list
	if _, ok := mgr.GetJobIMSIList(job.ID); ok {
		t.Error("should not have IMSI list initially")
	}

	// Set IMSI list
	imsiList := []string{"460110000000001", "460110000000002"}
	mgr.SetJobIMSIList(job.ID, imsiList)

	// Get IMSI list
	retrieved, ok := mgr.GetJobIMSIList(job.ID)
	if !ok {
		t.Error("should have IMSI list now")
	}
	if len(retrieved) != 2 {
		t.Errorf("expected 2 IMSIs, got %d", len(retrieved))
	}
}

func TestManagerExportCache(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uepcap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	mgr := NewManager(tmpDir, 1*time.Hour)
	job, _ := mgr.CreateJob()

	// Initially no cache
	if _, ok := mgr.GetCachedExport(job.ID, "key1"); ok {
		t.Error("should not have cached export initially")
	}

	// Cache export
	mgr.CacheExport(job.ID, "key1", "/path/to/export.pcap")

	// Get cached export
	path, ok := mgr.GetCachedExport(job.ID, "key1")
	if !ok {
		t.Error("should have cached export now")
	}
	if path != "/path/to/export.pcap" {
		t.Errorf("unexpected cached path: %s", path)
	}
}
