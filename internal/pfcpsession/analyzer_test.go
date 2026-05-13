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

	if result.Statistics.TotalTransactions != 2 {
		t.Fatalf("total transactions = %d, want 2", result.Statistics.TotalTransactions)
	}
	if result.Statistics.Success != 1 {
		t.Fatalf("success = %d, want 1", result.Statistics.Success)
	}
	if result.Statistics.Retransmit != 1 {
		t.Fatalf("retransmit = %d, want 1", result.Statistics.Retransmit)
	}
	if result.Transactions[1].Status != StatusNoResponse {
		t.Fatalf("second transaction status = %s, want %s", result.Transactions[1].Status, StatusNoResponse)
	}
	if result.Transactions[1].RetransmitCount != 1 {
		t.Fatalf("second transaction retransmit count = %d, want 1", result.Transactions[1].RetransmitCount)
	}
	if got := *result.Transactions[0].ResponseTimeMs; got != 25 {
		t.Fatalf("response time = %v, want 25", got)
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

func ptrUint8(v uint8) *uint8 {
	return &v
}
