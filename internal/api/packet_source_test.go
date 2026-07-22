package api

import (
	"testing"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/nasanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/ngapanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
	"gitee.com/yangdadayyds/uepcap/internal/s11analyzer"
)

func TestPacketSourceIndexLookup(t *testing.T) {
	timestamp := time.Unix(100, 123)
	index := &packetSourceIndex{sources: make(map[string]map[string]bool)}
	index.add(timestamp, "127.0.0.1", "127.0.0.3", "source-a.pcap")

	if got := index.lookup(timestamp, "127.0.0.1", "127.0.0.3"); got != "source-a.pcap" {
		t.Fatalf("lookup = %q, want source-a.pcap", got)
	}
	index.add(timestamp, "127.0.0.1", "127.0.0.3", "source-b.pcap")
	if got := index.lookup(timestamp, "127.0.0.1", "127.0.0.3"); got != "" {
		t.Fatalf("ambiguous lookup = %q, want empty", got)
	}
}

func TestAnnotateProtocolSourceFiles(t *testing.T) {
	requestTime := time.Unix(100, 123)
	responseTime := time.Unix(101, 456)
	index := &packetSourceIndex{sources: make(map[string]map[string]bool)}
	index.add(requestTime, "10.0.0.1", "10.0.0.2", "request.pcap")
	index.add(responseTime, "10.0.0.2", "10.0.0.1", "response.pcap")

	ngapResult := &ngapanalyzer.AnalysisResult{
		Messages: []*ngapanalyzer.Message{
			{FrameNumber: 10, Timestamp: requestTime, SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2"},
			{FrameNumber: 20, Timestamp: responseTime, SourceIP: "10.0.0.2", DestinationIP: "10.0.0.1"},
		},
		Transactions: []*ngapanalyzer.Transaction{{StartFrame: 10, EndFrame: 20}},
	}
	annotateNGAPSourceFiles(ngapResult, index)
	if ngapResult.Transactions[0].SourceFile != "request.pcap" || ngapResult.Transactions[0].ResponseFile != "response.pcap" {
		t.Fatalf("unexpected NGAP sources: %#v", ngapResult.Transactions[0])
	}

	nasResult := &nasanalyzer.AnalysisResult{
		Messages: []*nasanalyzer.Message{
			{FrameNumber: 10, Timestamp: requestTime, SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2"},
			{FrameNumber: 20, Timestamp: responseTime, SourceIP: "10.0.0.2", DestinationIP: "10.0.0.1"},
		},
		Flows: []*nasanalyzer.Flow{{StartFrame: 10, EndFrame: 20}},
	}
	annotateNASSourceFiles(nasResult, index)
	if nasResult.Flows[0].SourceFile != "request.pcap" || nasResult.Flows[0].ResponseFile != "response.pcap" {
		t.Fatalf("unexpected NAS sources: %#v", nasResult.Flows[0])
	}

	pfcpResult := &pfcpsession.AnalysisResult{Transactions: []*pfcpsession.Transaction{{
		RequestTime: requestTime, ResponseTime: &responseTime, SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2",
	}}}
	annotatePFCPSourceFiles(pfcpResult, index)
	if pfcpResult.Transactions[0].SourceFile != "request.pcap" || pfcpResult.Transactions[0].ResponseFile != "response.pcap" {
		t.Fatalf("unexpected PFCP sources: %#v", pfcpResult.Transactions[0])
	}

	s11Result := &s11analyzer.AnalysisResult{
		Messages: []*s11analyzer.Message{
			{FrameNumber: 10, Timestamp: requestTime, SourceIP: "10.0.0.1", DestinationIP: "10.0.0.2"},
			{FrameNumber: 20, Timestamp: responseTime, SourceIP: "10.0.0.2", DestinationIP: "10.0.0.1"},
		},
		Transactions: []*s11analyzer.Transaction{{RequestFrame: 10, ResponseFrame: 20}},
	}
	annotateS11SourceFiles(s11Result, index)
	if s11Result.Transactions[0].SourceFile != "request.pcap" || s11Result.Transactions[0].ResponseFile != "response.pcap" {
		t.Fatalf("unexpected S11 sources: %#v", s11Result.Transactions[0])
	}
}

func TestParsePacketSourceLine(t *testing.T) {
	timestamp, sourceIP, destinationIP, ok := parsePacketSourceLine("1784632455.239096000\t127.0.0.1\t127.0.0.3\t\t")
	if !ok || timestamp.IsZero() || sourceIP != "127.0.0.1" || destinationIP != "127.0.0.3" {
		t.Fatalf("unexpected parsed source row: %v %q %q %t", timestamp, sourceIP, destinationIP, ok)
	}
}
