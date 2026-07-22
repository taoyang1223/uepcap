package s11analyzer

import (
	"testing"
	"time"
)

func TestAnalyzeTransactionsParsesHexSequence(t *testing.T) {
	base := time.Unix(0, 0)
	messages := []*Message{
		{
			FrameNumber:     38899,
			Timestamp:       base,
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.1",
			MessageTypeCode: 99,
			MessageType:     MessageTypeName(99),
			SequenceNumber:  parseInt("0x000021"),
		},
		{
			FrameNumber:     38900,
			Timestamp:       base.Add(8 * time.Millisecond),
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.1",
			MessageTypeCode: 99,
			MessageType:     MessageTypeName(99),
			SequenceNumber:  parseInt("0x000021"),
		},
		{
			FrameNumber:     38909,
			Timestamp:       base.Add(64 * time.Millisecond),
			SourceIP:        "127.0.0.1",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 100,
			MessageType:     MessageTypeName(100),
			SequenceNumber:  parseInt("0x000021"),
			Cause:           "16",
			CauseName:       CauseName("16"),
		},
		{
			FrameNumber:     38910,
			Timestamp:       base.Add(65 * time.Millisecond),
			SourceIP:        "127.0.0.1",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 3,
			MessageType:     MessageTypeName(3),
			SequenceNumber:  99,
		},
	}

	result := NewAnalyzer().analyze("sample.pcap", messages)
	if len(result.Transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(result.Transactions))
	}

	tx := result.Transactions[0]
	if tx.SequenceNumber != 33 {
		t.Fatalf("expected sequence 33, got %d", tx.SequenceNumber)
	}
	if tx.RetransmitCount != 1 {
		t.Fatalf("expected one retransmit, got %d", tx.RetransmitCount)
	}
	if tx.Status != StatusSuccess {
		t.Fatalf("expected success, got %s", tx.Status)
	}
	if result.Statistics.Retransmit != 1 {
		t.Fatalf("expected retransmit statistic 1, got %d", result.Statistics.Retransmit)
	}
	if result.TotalPackets != 4 {
		t.Fatalf("expected total packets 4, got %d", result.TotalPackets)
	}
	if result.Statistics.TotalMessages != 3 {
		t.Fatalf("expected total S11 transaction messages 3, got %d", result.Statistics.TotalMessages)
	}
	if result.Statistics.TotalTransactions != 2 {
		t.Fatalf("expected total S11 request transactions 2, got %d", result.Statistics.TotalTransactions)
	}
	if result.Statistics.SuccessRate != 100 {
		t.Fatalf("expected success rate 100, got %.1f", result.Statistics.SuccessRate)
	}
}

func TestAnalyzeTransactionsIncludesIndirectDataForwardingTunnel(t *testing.T) {
	base := time.Unix(0, 0)
	messages := []*Message{
		{
			FrameNumber:     10,
			Timestamp:       base,
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.1",
			MessageTypeCode: 166,
			MessageType:     MessageTypeName(166),
			SequenceNumber:  7,
		},
		{
			FrameNumber:     11,
			Timestamp:       base.Add(time.Millisecond),
			SourceIP:        "127.0.0.1",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 167,
			MessageType:     MessageTypeName(167),
			SequenceNumber:  7,
			Cause:           "16",
			CauseName:       CauseName("16"),
		},
		{
			FrameNumber:     12,
			Timestamp:       base.Add(2 * time.Millisecond),
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.1",
			MessageTypeCode: 168,
			MessageType:     MessageTypeName(168),
			SequenceNumber:  8,
		},
		{
			FrameNumber:     13,
			Timestamp:       base.Add(3 * time.Millisecond),
			SourceIP:        "127.0.0.1",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 169,
			MessageType:     MessageTypeName(169),
			SequenceNumber:  8,
			Cause:           "16",
			CauseName:       CauseName("16"),
		},
	}

	result := NewAnalyzer().analyze("sample.pcap", messages)
	if result.Statistics.TotalMessages != 4 {
		t.Fatalf("total S11 transaction messages = %d, want 4", result.Statistics.TotalMessages)
	}
	if result.Statistics.TotalTransactions != 2 {
		t.Fatalf("total S11 transactions = %d, want 2", result.Statistics.TotalTransactions)
	}
	if result.Statistics.Successful != 2 {
		t.Fatalf("successful transactions = %d, want 2", result.Statistics.Successful)
	}
	if result.ProcedureStats[0].Name != "Create Indirect Data Forwarding Tunnel" {
		t.Fatalf("first procedure = %q", result.ProcedureStats[0].Name)
	}
}

func TestAnalyzeTransactionsIncludesExpandedGTPv2Pairs(t *testing.T) {
	base := time.Unix(0, 0)
	pairs := []struct {
		req       int
		resp      int
		procedure string
	}{
		{1, 2, "Echo"},
		{40, 41, "Remote UE Report"},
		{128, 129, "Identification"},
		{133, 134, "Forward Relocation"},
		{164, 165, "Resume"},
		{176, 177, "Downlink Data"},
		{200, 201, "Update PDN Connection Set"},
		{231, 232, "MBMS Session Start"},
	}

	messages := make([]*Message, 0, len(pairs)*2)
	for i, pair := range pairs {
		seq := i + 1
		req := &Message{
			FrameNumber:     seq*10 + 1,
			Timestamp:       base.Add(time.Duration(seq) * time.Millisecond),
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.1",
			MessageTypeCode: pair.req,
			MessageType:     MessageTypeName(pair.req),
			SequenceNumber:  seq,
		}
		resp := &Message{
			FrameNumber:     seq*10 + 2,
			Timestamp:       req.Timestamp.Add(time.Millisecond),
			SourceIP:        "127.0.0.1",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: pair.resp,
			MessageType:     MessageTypeName(pair.resp),
			SequenceNumber:  seq,
			Cause:           "16",
			CauseName:       CauseName("16"),
		}
		messages = append(messages, req, resp)
	}

	result := NewAnalyzer().analyze("sample.pcap", messages)
	if len(result.Transactions) != len(pairs) {
		t.Fatalf("transactions = %d, want %d", len(result.Transactions), len(pairs))
	}
	if result.Statistics.Successful != len(pairs) {
		t.Fatalf("successful transactions = %d, want %d", result.Statistics.Successful, len(pairs))
	}
	if result.Statistics.Requests != len(pairs) {
		t.Fatalf("requests = %d, want %d", result.Statistics.Requests, len(pairs))
	}
	if result.Statistics.Responses != len(pairs) {
		t.Fatalf("responses = %d, want %d", result.Statistics.Responses, len(pairs))
	}
	for i, pair := range pairs {
		if result.Transactions[i].Procedure != pair.procedure {
			t.Fatalf("transaction %d procedure = %q, want %q", i, result.Transactions[i].Procedure, pair.procedure)
		}
	}
}

func TestMessagesWithoutExplicitResponseDoNotCreateTransactions(t *testing.T) {
	base := time.Unix(0, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.1",
			MessageTypeCode: 64,
			MessageType:     MessageTypeName(64),
			SequenceNumber:  1,
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(time.Millisecond),
			SourceIP:        "127.0.0.1",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 65,
			MessageType:     MessageTypeName(65),
			SequenceNumber:  1,
			Cause:           "72",
			CauseName:       CauseName("72"),
		},
	}

	result := NewAnalyzer().analyze("sample.pcap", messages)
	if len(result.Transactions) != 0 {
		t.Fatalf("transactions = %d, want 0", len(result.Transactions))
	}
	if result.Statistics.TotalMessages != 0 {
		t.Fatalf("transaction messages = %d, want 0", result.Statistics.TotalMessages)
	}
	if result.TypeStats[0].Name != "Modify Bearer Command" {
		t.Fatalf("first type stat name = %q", result.TypeStats[0].Name)
	}
}
