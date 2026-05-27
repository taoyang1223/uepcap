package ngapanalyzer

import (
	"testing"
	"time"
)

func TestTransactionsDoNotCrossPeerPairs(t *testing.T) {
	base := time.Unix(100, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "10.0.0.11",
			DestinationIP:   "10.0.0.1",
			ProcedureCode:   "29",
			ProcedureName:   ProcedureName("29"),
			PDUType:         PDUInitiating,
			RANUENGAPID:     "7",
			AMFUENGAPID:     "99",
			WiresharkFilter: "frame.number == 1",
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(time.Millisecond),
			SourceIP:        "10.0.0.10",
			DestinationIP:   "10.0.0.1",
			ProcedureCode:   "29",
			ProcedureName:   ProcedureName("29"),
			PDUType:         PDUInitiating,
			RANUENGAPID:     "7",
			AMFUENGAPID:     "99",
			WiresharkFilter: "frame.number == 2",
		},
		{
			FrameNumber:     3,
			Timestamp:       base.Add(2 * time.Millisecond),
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.10",
			ProcedureCode:   "29",
			ProcedureName:   ProcedureName("29"),
			PDUType:         PDUSuccessfulOutcome,
			RANUENGAPID:     "7",
			AMFUENGAPID:     "99",
			WiresharkFilter: "frame.number == 3",
		},
	}

	result := analyze("sample.pcap", messages)
	if result.Statistics.SuccessfulTransactions != 1 || result.Statistics.InProgressTransactions != 1 {
		t.Fatalf("success/in-progress = %d/%d, want 1/1", result.Statistics.SuccessfulTransactions, result.Statistics.InProgressTransactions)
	}
	if result.Transactions[0].Status != TransactionInProgress {
		t.Fatalf("first transaction status = %s, want in_progress", result.Transactions[0].Status)
	}
	if result.Transactions[1].Status != TransactionSuccess {
		t.Fatalf("second transaction status = %s, want success", result.Transactions[1].Status)
	}
}
