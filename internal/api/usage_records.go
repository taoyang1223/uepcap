package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxUsageRecords = 10

type UsageRecordFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type UsageRecord struct {
	ID        string            `json:"id"`
	JobID     string            `json:"job_id"`
	CreatedAt time.Time         `json:"created_at"`
	FileCount int               `json:"file_count"`
	TotalSize int64             `json:"total_size"`
	Files     []UsageRecordFile `json:"files"`
}

type usageRecordStore struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

func newUsageRecordStore(dataDir string) *usageRecordStore {
	return &usageRecordStore{
		path: filepath.Join(dataDir, "usage_records.json"),
		now:  time.Now,
	}
}

func (s *usageRecordStore) Add(record UsageRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if record.JobID == "" {
		return fmt.Errorf("usage record job id is required")
	}
	if record.ID == "" {
		record.ID = record.JobID
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = s.now()
	}

	records, err := s.readLocked()
	if err != nil {
		return err
	}
	records = append([]UsageRecord{record}, records...)
	records = pruneUsageRecords(records, s.now())
	return s.writeLocked(records)
}

func (s *usageRecordStore) List() ([]UsageRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.readLocked()
	if err != nil {
		return nil, err
	}
	pruned := pruneUsageRecords(records, s.now())
	if !usageRecordsEqual(records, pruned) {
		if err := s.writeLocked(pruned); err != nil {
			return nil, err
		}
	}
	return pruned, nil
}

func (s *usageRecordStore) Delete(id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, fmt.Errorf("usage record id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	records, err := s.readLocked()
	if err != nil {
		return false, err
	}

	pruned := pruneUsageRecords(records, s.now())
	next := make([]UsageRecord, 0, len(pruned))
	deleted := false
	for _, record := range pruned {
		if record.ID == id || record.JobID == id {
			deleted = true
			continue
		}
		next = append(next, record)
	}

	if deleted || !usageRecordsEqual(records, pruned) {
		if err := s.writeLocked(next); err != nil {
			return false, err
		}
	}
	return deleted, nil
}

func (s *usageRecordStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.writeLocked(nil)
}

func (s *usageRecordStore) readLocked() ([]UsageRecord, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	var records []UsageRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (s *usageRecordStore) writeLocked(records []UsageRecord) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0755); err != nil {
		return err
	}
	if records == nil {
		records = []UsageRecord{}
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}

func pruneUsageRecords(records []UsageRecord, now time.Time) []UsageRecord {
	sort.SliceStable(records, func(i, j int) bool {
		return records[i].CreatedAt.After(records[j].CreatedAt)
	})

	out := make([]UsageRecord, 0, maxUsageRecords)
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if !sameLocalDay(record.CreatedAt, now) {
			continue
		}
		key := record.JobID
		if key == "" {
			key = record.ID
		}
		if key != "" {
			if seen[key] {
				continue
			}
			seen[key] = true
		}
		out = append(out, record)
		if len(out) == maxUsageRecords {
			break
		}
	}
	return out
}

func sameLocalDay(value, now time.Time) bool {
	location := now.Location()
	y1, m1, d1 := value.In(location).Date()
	y2, m2, d2 := now.In(location).Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

func usageRecordsEqual(a, b []UsageRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].JobID != b[i].JobID || !a[i].CreatedAt.Equal(b[i].CreatedAt) {
			return false
		}
	}
	return true
}

func (h *Handler) ListUsageRecords(w http.ResponseWriter, r *http.Request) {
	records, err := h.usageRecords.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to read usage records: %v", err))
		return
	}
	writeSuccess(w, records)
}

func (h *Handler) DeleteUsageRecord(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	deleted, err := h.usageRecords.Delete(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !deleted {
		writeError(w, http.StatusNotFound, "usage record not found")
		return
	}
	writeSuccess(w, map[string]string{"id": id})
}

func (h *Handler) ClearUsageRecords(w http.ResponseWriter, r *http.Request) {
	if err := h.usageRecords.Clear(); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to clear usage records: %v", err))
		return
	}
	writeSuccess(w, map[string]string{"message": "usage records cleared"})
}
