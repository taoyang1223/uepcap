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
	}

	result := NewAnalyzer().analyze("sample.pcap", messages)
	if len(result.Transactions) != 1 {
		t.Fatalf("expected 1 transaction, got %d", len(result.Transactions))
	}

	tx := result.Transactions[0]
	if tx.SequenceNumber != 33 {
		t.Fatalf("expected sequence 33, got %d", tx.SequenceNumber)
	}
	if tx.RetransmitCount != 0 {
		t.Fatalf("expected no retransmit, got %d", tx.RetransmitCount)
	}
	if tx.Status != StatusSuccess {
		t.Fatalf("expected success, got %s", tx.Status)
	}
	if result.Statistics.Retransmit != 0 {
		t.Fatalf("expected retransmit statistic 0, got %d", result.Statistics.Retransmit)
	}
}
