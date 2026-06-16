package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/job"
	"gitee.com/yangdadayyds/uepcap/internal/nasanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/ngapanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
	"gitee.com/yangdadayyds/uepcap/internal/s11analyzer"
	"gitee.com/yangdadayyds/uepcap/internal/s1apanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/statistics"
)

func TestMessageHandlersRestoreJobsFromDisk(t *testing.T) {
	dataDir := t.TempDir()
	jobID := "restored-job"
	jobDir := filepath.Join(dataDir, "tmp", jobID)
	if err := os.MkdirAll(jobDir, 0755); err != nil {
		t.Fatalf("create job dir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, "merged.pcap"), []byte("pcap data"), 0644); err != nil {
		t.Fatalf("write merged pcap failed: %v", err)
	}

	handler := NewHandler(job.NewManagerWithLimit(dataDir, time.Hour, 3))
	seedRestoredMessageHandlerCaches(handler, jobID)

	tests := []struct {
		name    string
		path    string
		handler func(http.ResponseWriter, *http.Request)
		stream  bool
	}{
		{name: "message stats", path: "/api/jobs/" + jobID + "/message-stats", handler: handler.GetMessageStats},
		{name: "message stats stream", path: "/api/jobs/" + jobID + "/message-stats/stream", handler: handler.StreamMessageStats, stream: true},
		{name: "ngap messages", path: "/api/jobs/" + jobID + "/ngap-messages", handler: handler.GetNGAPMessages},
		{name: "ngap messages stream", path: "/api/jobs/" + jobID + "/ngap-messages/stream", handler: handler.StreamNGAPMessages, stream: true},
		{name: "s1ap messages", path: "/api/jobs/" + jobID + "/s1ap-messages", handler: handler.GetS1APMessages},
		{name: "s1ap messages stream", path: "/api/jobs/" + jobID + "/s1ap-messages/stream", handler: handler.StreamS1APMessages, stream: true},
		{name: "nas messages", path: "/api/jobs/" + jobID + "/nas-messages", handler: handler.GetNASMessages},
		{name: "nas messages stream", path: "/api/jobs/" + jobID + "/nas-messages/stream", handler: handler.StreamNASMessages, stream: true},
		{name: "sm nas messages", path: "/api/jobs/" + jobID + "/sm-nas-messages", handler: handler.GetSMNASMessages},
		{name: "sm nas messages stream", path: "/api/jobs/" + jobID + "/sm-nas-messages/stream", handler: handler.StreamSMNASMessages, stream: true},
		{name: "s11 messages", path: "/api/jobs/" + jobID + "/s11-messages", handler: handler.GetS11Messages},
		{name: "s11 messages stream", path: "/api/jobs/" + jobID + "/s11-messages/stream", handler: handler.StreamS11Messages, stream: true},
		{name: "pfcp sessions", path: "/api/jobs/" + jobID + "/pfcp-sessions", handler: handler.GetPFCPSessions},
		{name: "pfcp sessions stream", path: "/api/jobs/" + jobID + "/pfcp-sessions/stream", handler: handler.StreamPFCPSessions, stream: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.path, bytes.NewBufferString(`{}`))
			req.SetPathValue("id", jobID)
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("%s status = %d, body = %s", tt.name, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "job not found") {
				t.Fatalf("%s returned job not found: %s", tt.name, rec.Body.String())
			}
			if tt.stream && !strings.Contains(rec.Body.String(), "event: done") {
				t.Fatalf("%s did not emit done event: %s", tt.name, rec.Body.String())
			}
		})
	}
}

func seedRestoredMessageHandlerCaches(handler *Handler, jobID string) {
	handler.messageStats.mu.Lock()
	handler.messageStats.results[messageStatsCacheKey(jobID, nil)] = &statistics.Result{}
	handler.messageStats.mu.Unlock()

	handler.analysis.set(jobID+"|ngap-v5", &ngapanalyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|ngap-v5-stream", &ngapanalyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|s1ap-v4", &s1apanalyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|s1ap-v5-stream", &s1apanalyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|nas-v2", &nasanalyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|sm-nas-v2", &nasanalyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|nas-v3-stream", &nasanalyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|s11-v2", &s11analyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|s11-v3-stream", &s11analyzer.AnalysisResult{})
	handler.analysis.set(jobID+"|pfcp-transaction-v10|timeout=0", &pfcpsession.AnalysisResult{})
	handler.analysis.set(jobID+"|pfcp-transaction-v10-stream|timeout=0", &pfcpsession.AnalysisResult{})
}
