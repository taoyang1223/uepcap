package api

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/job"
)

func TestCreateJobStreamsUploadToDisk(t *testing.T) {
	dataDir := t.TempDir()
	handler := NewHandler(job.NewManagerWithLimit(dataDir, time.Hour, 3))

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", "capture.pcap00")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := part.Write([]byte("pcap data")); err != nil {
		t.Fatalf("part write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer close failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/jobs", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	handler.CreateJob(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("CreateJob status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp APIResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response decode failed: %v", err)
	}
	data, ok := resp.Data.(map[string]any)
	if !ok {
		t.Fatalf("response data type = %T", resp.Data)
	}
	mergedPath, ok := data["merged_pcap"].(string)
	if !ok || mergedPath == "" {
		t.Fatalf("merged_pcap missing in response: %#v", data)
	}
	if _, err := os.Stat(mergedPath); err != nil {
		t.Fatalf("merged pcap was not saved: %v", err)
	}
	if filepath.Base(mergedPath) != "merged.pcap" {
		t.Fatalf("merged path = %q, want merged.pcap", mergedPath)
	}
}

func TestCreateJobRejectsUnsupportedFileType(t *testing.T) {
	handler := NewHandler(job.NewManagerWithLimit(t.TempDir(), time.Hour, 3))

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", "capture.txt")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := part.Write([]byte("not pcap")); err != nil {
		t.Fatalf("part write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer close failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/jobs", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	handler.CreateJob(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("CreateJob status = %d, want %d; body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestCreateJobWritesUsageRecord(t *testing.T) {
	dataDir := t.TempDir()
	handler := NewHandler(job.NewManagerWithLimit(dataDir, time.Hour, 3))

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("files", "capture.pcap")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	if _, err := part.Write([]byte("pcap data")); err != nil {
		t.Fatalf("part write failed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("writer close failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/jobs", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	handler.CreateJob(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("CreateJob status = %d, body = %s", rec.Code, rec.Body.String())
	}

	records, err := handler.usageRecords.List()
	if err != nil {
		t.Fatalf("List usage records failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("usage record count = %d, want 1", len(records))
	}
	if records[0].FileCount != 1 || records[0].TotalSize != int64(len("pcap data")) {
		t.Fatalf("usage record file summary = count %d size %d", records[0].FileCount, records[0].TotalSize)
	}
	if len(records[0].Files) != 1 || records[0].Files[0].Name != "capture.pcap" {
		t.Fatalf("usage record files = %#v", records[0].Files)
	}
}
