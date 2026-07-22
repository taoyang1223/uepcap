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

func TestManagerRestoreJob(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uepcap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	jobID := "78b52698-b8fc-4d42-a90a-11579331df03"
	jobDir := filepath.Join(tmpDir, "tmp", jobID)
	if err := os.MkdirAll(jobDir, 0755); err != nil {
		t.Fatalf("failed to create job dir: %v", err)
	}
	mergedPcap := filepath.Join(jobDir, "merged.pcap")
	if err := os.WriteFile(mergedPcap, []byte("pcap"), 0644); err != nil {
		t.Fatalf("failed to write merged pcap: %v", err)
	}

	mgr := NewManager(tmpDir, 1*time.Hour)
	restored, ok := mgr.RestoreJob(jobID)
	if !ok {
		t.Fatal("RestoreJob should restore existing merged pcap")
	}
	if restored.ID != jobID {
		t.Errorf("unexpected restored job ID: %s", restored.ID)
	}
	if restored.MergedPcap != mergedPcap {
		t.Errorf("unexpected merged pcap path: %s", restored.MergedPcap)
	}
	if restored.IMSIScanned {
		t.Error("restored job should not reuse stale IMSI scan state")
	}

	if _, ok := mgr.RestoreJob("../bad"); ok {
		t.Error("RestoreJob should reject path-like IDs")
	}
}

func TestManagerRestoreJobPreservesOriginalFiles(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := NewManager(tmpDir, time.Hour)
	created, err := mgr.CreateJob()
	if err != nil {
		t.Fatalf("CreateJob failed: %v", err)
	}
	jobDir := mgr.GetJobDir(created.ID)
	mergedPcap := filepath.Join(jobDir, "merged.pcap")
	if err := os.WriteFile(mergedPcap, []byte("pcap"), 0644); err != nil {
		t.Fatalf("write merged pcap failed: %v", err)
	}
	originalFiles := []string{
		filepath.Join(jobDir, "source-a.pcap.gz"),
		filepath.Join(jobDir, "source-b.pcapng"),
	}
	mgr.SetJobMergedPcap(created.ID, mergedPcap, originalFiles)

	restarted := NewManager(tmpDir, time.Hour)
	restored, ok := restarted.RestoreJob(created.ID)
	if !ok {
		t.Fatal("RestoreJob should restore persisted job")
	}
	if len(restored.OriginalFiles) != 2 || restored.OriginalFiles[0] != originalFiles[0] || restored.OriginalFiles[1] != originalFiles[1] {
		t.Fatalf("restored original files = %#v, want %#v", restored.OriginalFiles, originalFiles)
	}
}

func TestManagerRestoreLegacyJobUsesUsageRecordFiles(t *testing.T) {
	tmpDir := t.TempDir()
	jobID := "legacy-job"
	jobDir := filepath.Join(tmpDir, "tmp", jobID)
	if err := os.MkdirAll(jobDir, 0755); err != nil {
		t.Fatalf("create job dir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "merged.pcap"), []byte("pcap"), 0644); err != nil {
		t.Fatalf("write merged pcap failed: %v", err)
	}
	usageRecords := `[{"job_id":"legacy-job","files":[{"name":"source-a.pcap.gz"},{"name":"source-b.pcap7"}]}]`
	if err := os.WriteFile(filepath.Join(tmpDir, "usage_records.json"), []byte(usageRecords), 0644); err != nil {
		t.Fatalf("write usage records failed: %v", err)
	}

	restored, ok := NewManager(tmpDir, time.Hour).RestoreJob(jobID)
	if !ok {
		t.Fatal("RestoreJob should restore legacy job")
	}
	if len(restored.OriginalFiles) != 2 {
		t.Fatalf("restored original files = %#v, want two files", restored.OriginalFiles)
	}
	if filepath.Base(restored.OriginalFiles[0]) != "source-a.pcap.gz" || filepath.Base(restored.OriginalFiles[1]) != "source-b.pcap7" {
		t.Fatalf("unexpected restored original files: %#v", restored.OriginalFiles)
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

func TestManagerAutoCleanupOldJobs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uepcap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create manager with max 3 jobs limit
	mgr := NewManagerWithLimit(tmpDir, 1*time.Hour, 3)

	// Create 3 jobs
	var jobIDs []string
	for i := 0; i < 3; i++ {
		job, err := mgr.CreateJob()
		if err != nil {
			t.Fatalf("CreateJob %d failed: %v", i, err)
		}
		jobIDs = append(jobIDs, job.ID)
		// Small delay to ensure different creation times
		time.Sleep(10 * time.Millisecond)
	}

	// Verify 3 jobs exist
	jobs := mgr.ListJobs()
	if len(jobs) != 3 {
		t.Errorf("expected 3 jobs, got %d", len(jobs))
	}

	// Create 4th job - should trigger cleanup of oldest job
	job4, err := mgr.CreateJob()
	if err != nil {
		t.Fatalf("CreateJob 4th failed: %v", err)
	}

	// Verify still 3 jobs (oldest was cleaned)
	jobs = mgr.ListJobs()
	if len(jobs) != 3 {
		t.Errorf("expected 3 jobs after cleanup, got %d", len(jobs))
	}

	// Verify oldest job was deleted
	if _, ok := mgr.GetJob(jobIDs[0]); ok {
		t.Error("oldest job should have been deleted")
	}

	// Verify newer jobs still exist
	if _, ok := mgr.GetJob(jobIDs[1]); !ok {
		t.Error("2nd job should still exist")
	}
	if _, ok := mgr.GetJob(jobIDs[2]); !ok {
		t.Error("3rd job should still exist")
	}
	if _, ok := mgr.GetJob(job4.ID); !ok {
		t.Error("4th job should exist")
	}
}

func TestManagerUnlimitedJobs(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "uepcap-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create manager with no limit (maxJobs = 0)
	mgr := NewManagerWithLimit(tmpDir, 1*time.Hour, 0)

	// Create 5 jobs
	for i := 0; i < 5; i++ {
		_, err := mgr.CreateJob()
		if err != nil {
			t.Fatalf("CreateJob %d failed: %v", i, err)
		}
	}

	// All 5 jobs should exist
	jobs := mgr.ListJobs()
	if len(jobs) != 5 {
		t.Errorf("expected 5 jobs, got %d", len(jobs))
	}
}
