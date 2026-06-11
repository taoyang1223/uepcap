package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUsageRecordStoreKeepsOnlyTodayLatestTen(t *testing.T) {
	dataDir := t.TempDir()
	store := newUsageRecordStore(dataDir)
	now := time.Date(2026, 6, 1, 16, 30, 0, 0, time.Local)
	store.now = func() time.Time { return now }

	if err := store.Add(UsageRecord{
		JobID:     "yesterday",
		CreatedAt: now.AddDate(0, 0, -1),
		FileCount: 1,
		Files:     []UsageRecordFile{{Name: "old.pcap", Size: 1}},
	}); err != nil {
		t.Fatalf("Add yesterday record failed: %v", err)
	}
	for i := 0; i < 12; i++ {
		if err := store.Add(UsageRecord{
			JobID:     "today-" + string(rune('a'+i)),
			CreatedAt: now.Add(time.Duration(i) * time.Minute),
			FileCount: 1,
			Files:     []UsageRecordFile{{Name: "capture.pcap", Size: int64(i + 1)}},
		}); err != nil {
			t.Fatalf("Add today record %d failed: %v", i, err)
		}
	}

	records, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(records) != maxUsageRecords {
		t.Fatalf("record count = %d, want %d", len(records), maxUsageRecords)
	}
	if records[0].JobID != "today-l" {
		t.Fatalf("latest record = %q, want today-l", records[0].JobID)
	}
	for _, record := range records {
		if record.JobID == "yesterday" {
			t.Fatalf("yesterday record was not pruned")
		}
	}

	data, err := os.ReadFile(filepath.Join(dataDir, "usage_records.json"))
	if err != nil {
		t.Fatalf("Read usage record file failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("usage record file is empty")
	}
}

func TestUsageRecordStoreDeleteAndClear(t *testing.T) {
	dataDir := t.TempDir()
	store := newUsageRecordStore(dataDir)
	now := time.Date(2026, 6, 1, 16, 30, 0, 0, time.Local)
	store.now = func() time.Time { return now }

	for _, jobID := range []string{"job-a", "job-b"} {
		if err := store.Add(UsageRecord{
			JobID:     jobID,
			CreatedAt: now,
			FileCount: 1,
			Files:     []UsageRecordFile{{Name: jobID + ".pcap", Size: 1}},
		}); err != nil {
			t.Fatalf("Add %s failed: %v", jobID, err)
		}
	}

	deleted, err := store.Delete("job-a")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if !deleted {
		t.Fatalf("Delete returned false, want true")
	}

	records, err := store.List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(records) != 1 || records[0].JobID != "job-b" {
		t.Fatalf("records after delete = %#v, want only job-b", records)
	}

	deleted, err = store.Delete("missing")
	if err != nil {
		t.Fatalf("Delete missing failed: %v", err)
	}
	if deleted {
		t.Fatalf("Delete missing returned true, want false")
	}

	if err := store.Clear(); err != nil {
		t.Fatalf("Clear failed: %v", err)
	}
	records, err = store.List()
	if err != nil {
		t.Fatalf("List after clear failed: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records after clear = %#v, want empty", records)
	}
}
