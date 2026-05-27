package s1apanalyzer

import (
	"testing"
	"time"
)

func TestParseFieldRows(t *testing.T) {
	output := "10\t1710000000.100\t10.0.0.1\t10.0.0.2\t\t\t12\t0\t100\t200\t0x41\t\t\t\t\t\n" +
		"11\t1710000000.250\t10.0.0.2\t10.0.0.1\t\t\t9\t0\t100\t200\t\t\t0x01020304\t\t\t5\n" +
		"12\t1710000000.300\t10.0.0.1\t10.0.0.2\t\t\t9\t1\t100\t200\t\t\t\t0x01020304\t\t5\n"

	messages := parseFieldRows(output)
	if len(messages) != 3 {
		t.Fatalf("parseFieldRows() len = %d, want 3", len(messages))
	}
	if messages[0].ProcedureName != "Initial UE Message" {
		t.Fatalf("first procedure = %q", messages[0].ProcedureName)
	}
	if messages[0].Direction != DirectionENBToMME {
		t.Fatalf("initial UE direction = %q, want %q", messages[0].Direction, DirectionENBToMME)
	}
	if !messages[0].HasNAS {
		t.Fatal("first message HasNAS = false, want true")
	}
	if messages[1].Direction != DirectionMMEToENB {
		t.Fatalf("request direction = %q, want %q", messages[1].Direction, DirectionMMEToENB)
	}
	if messages[2].Direction != DirectionENBToMME {
		t.Fatalf("response direction = %q, want %q", messages[2].Direction, DirectionENBToMME)
	}
	if messages[1].GTPTEID != "0x01020304" || messages[1].ERABID != "5" {
		t.Fatalf("GTPTEID/ERABID = %q/%q", messages[1].GTPTEID, messages[1].ERABID)
	}
}

func TestAnalyzeTransactions(t *testing.T) {
	messages := parseFieldRows("1\t1710000000.000\t10.0.0.2\t10.0.0.1\t\t\t9\t0\t100\t200\t\t\t\t\t\t5\n" +
		"2\t1710000000.125\t10.0.0.1\t10.0.0.2\t\t\t9\t1\t100\t200\t\t\t\t\t\t5\n" +
		"3\t1710000001.000\t10.0.0.2\t10.0.0.1\t\t\t5\t0\t100\t200\t\t\t\t\t\t6\n")

	result := analyze("sample.pcap", messages)
	if result.Statistics.TotalMessages != 3 {
		t.Fatalf("total messages = %d, want 3", result.Statistics.TotalMessages)
	}
	if result.Statistics.TotalTransactions != 2 {
		t.Fatalf("total transactions = %d, want 2", result.Statistics.TotalTransactions)
	}
	if result.Statistics.SuccessfulTransactions != 1 || result.Statistics.InProgressTransactions != 1 {
		t.Fatalf("success/in-progress = %d/%d", result.Statistics.SuccessfulTransactions, result.Statistics.InProgressTransactions)
	}
	if result.Transactions[0].DurationMs != 125 {
		t.Fatalf("duration = %v, want 125", result.Transactions[0].DurationMs)
	}
	if result.Transactions[1].Status != TransactionInProgress {
		t.Fatalf("second transaction status = %q", result.Transactions[1].Status)
	}
}

func TestParseFieldRowsExpandsBundledS1APPDUs(t *testing.T) {
	messages := parseFieldRows("20\t1710000002.000\t10.0.0.1\t10.0.0.2\t\t\t13,9,13\t0,1,0\t100\t200\t0x42\t\t\t\t\t\n")

	if len(messages) != 3 {
		t.Fatalf("parseFieldRows() len = %d, want 3", len(messages))
	}
	wantProcedures := []string{"13", "9", "13"}
	wantPDUs := []PDUType{PDUInitiating, PDUSuccessfulOutcome, PDUInitiating}
	for i := range messages {
		if messages[i].ProcedureCode != wantProcedures[i] {
			t.Fatalf("message[%d] procedure = %q, want %q", i, messages[i].ProcedureCode, wantProcedures[i])
		}
		if messages[i].PDUType != wantPDUs[i] {
			t.Fatalf("message[%d] pdu = %q, want %q", i, messages[i].PDUType, wantPDUs[i])
		}
	}
}

func TestTransactionsDoNotCrossPeerPairs(t *testing.T) {
	base := time.Unix(100, 0)
	messages := []*Message{
		{
			FrameNumber:     1,
			Timestamp:       base,
			SourceIP:        "10.0.0.11",
			DestinationIP:   "10.0.0.1",
			ProcedureCode:   "17",
			ProcedureName:   ProcedureName("17"),
			PDUType:         PDUInitiating,
			MMEUES1APID:     "99",
			ENBUES1APID:     "7",
			WiresharkFilter: "frame.number == 1",
		},
		{
			FrameNumber:     2,
			Timestamp:       base.Add(time.Millisecond),
			SourceIP:        "10.0.0.10",
			DestinationIP:   "10.0.0.1",
			ProcedureCode:   "17",
			ProcedureName:   ProcedureName("17"),
			PDUType:         PDUInitiating,
			MMEUES1APID:     "99",
			ENBUES1APID:     "7",
			WiresharkFilter: "frame.number == 2",
		},
		{
			FrameNumber:     3,
			Timestamp:       base.Add(2 * time.Millisecond),
			SourceIP:        "10.0.0.1",
			DestinationIP:   "10.0.0.10",
			ProcedureCode:   "17",
			ProcedureName:   ProcedureName("17"),
			PDUType:         PDUSuccessfulOutcome,
			MMEUES1APID:     "99",
			ENBUES1APID:     "7",
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
