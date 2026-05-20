package pfcpsession

import (
	"testing"
	"time"
)

func TestAnalyzeMatchesSessionTransactions(t *testing.T) {
	base := time.Unix(100, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.2",
			MessageTypeCode: 50,
			HeaderSEID:      11,
			SequenceNumber:  7,
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(25 * time.Millisecond),
			SourceIP:        "10.0.0.2",
			DestinationIP:   "10.0.0.1",
			MessageTypeCode: 51,
			HeaderSEID:      22,
			SequenceNumber:  7,
			Cause:           ptrUint8(CauseRequestAccepted),
		},
		{
			FrameNumber:     3,
			Timestamp:       base.Add(time.Second),
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.2",
			MessageTypeCode: 52,
			HeaderSEID:      22,
			SequenceNumber:  8,
		},
		{
			FrameNumber:     4,
			Timestamp:       base.Add(1100 * time.Millisecond),
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.2",
			MessageTypeCode: 52,
			HeaderSEID:      22,
			SequenceNumber:  8,
		},
	}

	analyzer := NewAnalyzer()
	result := analyzer.analyze("sample.pcap", messages)

	if result.Statistics.TotalTransactions != 3 {
		t.Fatalf("total transactions = %d, want 3", result.Statistics.TotalTransactions)
	}
	if result.Statistics.Success != 1 {
		t.Fatalf("success = %d, want 1", result.Statistics.Success)
	}
	if result.Statistics.NoResponse != 2 {
		t.Fatalf("no response = %d, want 2", result.Statistics.NoResponse)
	}
	if result.Statistics.Retransmit != 1 {
		t.Fatalf("retransmit = %d, want 1", result.Statistics.Retransmit)
	}
	if result.Transactions[1].Status != StatusNoResponse {
		t.Fatalf("second transaction status = %s, want %s", result.Transactions[1].Status, StatusNoResponse)
	}
	if result.Transactions[2].Status != StatusNoResponse {
		t.Fatalf("third transaction status = %s, want %s", result.Transactions[2].Status, StatusNoResponse)
	}
	if result.Transactions[2].RetransmitCount != 1 {
		t.Fatalf("third transaction retransmit count = %d, want 1", result.Transactions[2].RetransmitCount)
	}
	if got := *result.Transactions[0].ResponseTimeMs; got != 25 {
		t.Fatalf("response time = %v, want 25", got)
	}
}

func TestAnalyzeAddsSessionSEIDFilterBesideTransactionFilter(t *testing.T) {
	base := time.Unix(150, 0)
	messages := []*Message{
		{
			FrameNumber:     90592,
			Timestamp:       base,
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.5",
			MessageTypeCode: 50,
			FSEID:           0x602EA88297F0A125,
			SequenceNumber:  61723,
		},
		{
			FrameNumber:     90593,
			Timestamp:       base.Add(time.Millisecond),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 51,
			HeaderSEID:      0x602EA88297F0A125,
			FSEID:           0x0000000000000190,
			SequenceNumber:  61723,
			Cause:           ptrUint8(CauseRequestAccepted),
		},
		{
			FrameNumber:     90680,
			Timestamp:       base.Add(2 * time.Millisecond),
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.5",
			MessageTypeCode: 50,
			FSEID:           0x6595C682AF233510,
			SequenceNumber:  63216,
		},
		{
			FrameNumber:     90681,
			Timestamp:       base.Add(3 * time.Millisecond),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 51,
			HeaderSEID:      0x6595C682AF233510,
			FSEID:           0x0000000000000194,
			SequenceNumber:  63216,
			Cause:           ptrUint8(CauseRequestAccepted),
		},
		{
			FrameNumber:     90706,
			Timestamp:       base.Add(4 * time.Millisecond),
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.5",
			MessageTypeCode: 50,
			FSEID:           0x602EA88297F0A125,
			SequenceNumber:  63221,
		},
		{
			FrameNumber:     90707,
			Timestamp:       base.Add(5 * time.Millisecond),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 51,
			HeaderSEID:      0x602EA88297F0A125,
			FSEID:           0x0000000000000196,
			SequenceNumber:  63221,
			Cause:           ptrUint8(CauseRequestAccepted),
		},
	}

	analyzer := NewAnalyzer()
	result := analyzer.analyze("sample.pcap", messages)

	if result.Statistics.TotalTransactions != 3 {
		t.Fatalf("total transactions = %d, want 3", result.Statistics.TotalTransactions)
	}
	tx := result.Transactions[2]
	wantFilter := "(pfcp.msg_type == 50 || pfcp.msg_type == 51) && pfcp.seqno == 63221 && ip.addr == 127.0.0.3 && ip.addr == 127.0.0.5"
	if got := tx.WiresharkFilter; got != wantFilter {
		t.Fatalf("wireshark filter = %q, want %q", got, wantFilter)
	}
	wantSEIDFilter := "(pfcp.seid == 0x602EA88297F0A125) || (pfcp.seid == 0x0000000000000190) || (pfcp.seid == 0x0000000000000196)"
	if got := tx.SEIDFilter; got != wantSEIDFilter {
		t.Fatalf("seid filter = %q, want %q", got, wantSEIDFilter)
	}
}

func TestAnalyzeDoesNotTreatSameSequenceDifferentSEIDAsRetransmit(t *testing.T) {
	base := time.Unix(200, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.2",
			MessageTypeCode: 52,
			HeaderSEID:      11,
			SequenceNumber:  9,
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(time.Millisecond),
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.2",
			MessageTypeCode: 52,
			HeaderSEID:      22,
			SequenceNumber:  9,
		},
	}

	analyzer := NewAnalyzer()
	result := analyzer.analyze("sample.pcap", messages)

	if result.Statistics.Retransmit != 0 {
		t.Fatalf("retransmit = %d, want 0", result.Statistics.Retransmit)
	}
}

func TestAnalyzeIncludesSessionReportTransactions(t *testing.T) {
	base := time.Unix(300, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "10.0.0.2",
			DestinationIP:   "10.0.0.1",
			MessageTypeCode: 56,
			HeaderSEID:      22,
			SequenceNumber:  10,
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(15 * time.Millisecond),
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.2",
			MessageTypeCode: 57,
			HeaderSEID:      22,
			SequenceNumber:  10,
			Cause:           ptrUint8(CauseRequestAccepted),
		},
	}

	analyzer := NewAnalyzer()
	result := analyzer.analyze("sample.pcap", messages)

	if result.Statistics.TotalTransactions != 1 {
		t.Fatalf("total transactions = %d, want 1", result.Statistics.TotalTransactions)
	}
	if result.Statistics.SessionReport != 1 {
		t.Fatalf("session report = %d, want 1", result.Statistics.SessionReport)
	}
	if result.Transactions[0].MessageType != "Session Report" {
		t.Fatalf("message type = %q, want Session Report", result.Transactions[0].MessageType)
	}
	if result.Transactions[0].Status != StatusSuccess {
		t.Fatalf("status = %s, want %s", result.Transactions[0].Status, StatusSuccess)
	}
}

func TestAnalyzeCountsUnansweredSessionReportRetransmits(t *testing.T) {
	base := time.Unix(350, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 56,
			HeaderSEID:      0x602ea88297f0a125,
			SequenceNumber:  1,
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(2 * time.Second),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 56,
			HeaderSEID:      0x602ea88297f0a125,
			SequenceNumber:  1,
		},
		{
			FrameNumber:     3,
			Timestamp:       base.Add(4 * time.Second),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 56,
			HeaderSEID:      0x602ea88297f0a125,
			SequenceNumber:  1,
		},
	}

	analyzer := NewAnalyzer()
	result := analyzer.analyze("sample.pcap", messages)

	if result.Statistics.TotalTransactions != 3 {
		t.Fatalf("total transactions = %d, want 3", result.Statistics.TotalTransactions)
	}
	if result.Statistics.NoResponse != 3 {
		t.Fatalf("no response = %d, want 3", result.Statistics.NoResponse)
	}
	if result.Statistics.SessionReport != 3 {
		t.Fatalf("session report = %d, want 3", result.Statistics.SessionReport)
	}
	if result.Statistics.Retransmit != 2 {
		t.Fatalf("retransmit = %d, want 2", result.Statistics.Retransmit)
	}
}

func TestAnalyzeIncludesNodeLevelTransactions(t *testing.T) {
	base := time.Unix(400, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.5",
			MessageTypeCode: 1,
			SequenceNumber:  100,
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(2 * time.Millisecond),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 2,
			SequenceNumber:  100,
		},
		{
			FrameNumber:     3,
			Timestamp:       base.Add(10 * time.Millisecond),
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.5",
			MessageTypeCode: 5,
			SequenceNumber:  101,
		},
		{
			FrameNumber:     4,
			Timestamp:       base.Add(14 * time.Millisecond),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 6,
			SequenceNumber:  101,
			Cause:           ptrUint8(CauseRequestAccepted),
		},
		{
			FrameNumber:     5,
			Timestamp:       base.Add(20 * time.Millisecond),
			SourceIP:        "127.0.0.3",
			DestinationIP:   "127.0.0.5",
			MessageTypeCode: 12,
			SequenceNumber:  102,
		},
		{
			FrameNumber:     6,
			Timestamp:       base.Add(25 * time.Millisecond),
			SourceIP:        "127.0.0.5",
			DestinationIP:   "127.0.0.3",
			MessageTypeCode: 13,
			SequenceNumber:  102,
		},
	}

	analyzer := NewAnalyzer()
	result := analyzer.analyze("sample.pcap", messages)

	if result.Statistics.TotalTransactions != 3 {
		t.Fatalf("total transactions = %d, want 3", result.Statistics.TotalTransactions)
	}
	if result.Statistics.Heartbeat != 1 {
		t.Fatalf("heartbeat = %d, want 1", result.Statistics.Heartbeat)
	}
	if result.Statistics.AssociationSetup != 1 {
		t.Fatalf("association setup = %d, want 1", result.Statistics.AssociationSetup)
	}
	if result.Statistics.NodeReport != 1 {
		t.Fatalf("node report = %d, want 1", result.Statistics.NodeReport)
	}
	if result.Statistics.Success != 3 {
		t.Fatalf("success = %d, want 3", result.Statistics.Success)
	}
	if result.Transactions[0].MessageType != "Heartbeat" {
		t.Fatalf("first message type = %q, want Heartbeat", result.Transactions[0].MessageType)
	}
	if result.Transactions[0].WiresharkFilter != "(pfcp.msg_type == 1 || pfcp.msg_type == 2) && pfcp.seqno == 100 && ip.addr == 127.0.0.3 && ip.addr == 127.0.0.5" {
		t.Fatalf("wireshark filter = %q", result.Transactions[0].WiresharkFilter)
	}
}

func ptrUint8(v uint8) *uint8 {
	return &v
}
