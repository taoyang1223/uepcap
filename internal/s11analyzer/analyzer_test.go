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
			MessageTypeCode: 1,
			MessageType:     MessageTypeName(1),
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
