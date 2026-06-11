package ngapanalyzer

import (
	"strings"
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

func TestHandoverProceduresAreNamedAndPaired(t *testing.T) {
	lines := []string{
		ngapFieldLine("10", "1.000", "10.18.11.210", "10.18.1.181", "12", "0", "14", "5"),
		ngapFieldLine("11", "1.010", "10.18.1.181", "10.18.11.210", "12", "1", "14", "5"),
		ngapFieldLine("12", "1.020", "10.18.1.181", "10.18.11.200", "13", "0", "68719476752", ""),
		ngapFieldLine("13", "1.030", "10.18.11.200", "10.18.1.181", "13", "1", "68719476752", "0"),
		ngapFieldLine("14", "1.040", "10.18.11.200", "10.18.1.181", "11", "0", "68719476752", "0"),
		ngapFieldLine("15", "1.050", "10.18.1.181", "10.18.11.200", "7", "0", "68719476752", "0"),
		ngapFieldLine("16", "1.060", "10.18.11.200", "10.18.1.181", "49", "0", "68719476752", "0"),
	}

	result := analyze("handover.pcap", parseFieldRows(strings.Join(lines, "\n")))
	if result.Statistics.TotalTransactions != 2 {
		t.Fatalf("total transactions = %d, want 2", result.Statistics.TotalTransactions)
	}
	if result.Statistics.SuccessfulTransactions != 2 {
		t.Fatalf("successful transactions = %d, want 2", result.Statistics.SuccessfulTransactions)
	}

	handoverPreparation := findProcedureStat(t, result, "12")
	if handoverPreparation.Name != "Handover Preparation" || !handoverPreparation.TransactionCapable || handoverPreparation.Count != 2 {
		t.Fatalf("procedure 12 = %+v, want named transaction-capable count 2", handoverPreparation)
	}

	handoverResourceAllocation := findProcedureStat(t, result, "13")
	if handoverResourceAllocation.Name != "Handover Resource Allocation" || !handoverResourceAllocation.TransactionCapable || handoverResourceAllocation.Count != 2 {
		t.Fatalf("procedure 13 = %+v, want named transaction-capable count 2", handoverResourceAllocation)
	}

	messageByFrame := make(map[int]*Message)
	for _, message := range result.Messages {
		messageByFrame[message.FrameNumber] = message
	}
	if messageByFrame[10].Direction != DirectionGNBToAMF {
		t.Fatalf("handover required direction = %s, want gnb_to_amf", messageByFrame[10].Direction)
	}
	if messageByFrame[11].Direction != DirectionAMFToGNB {
		t.Fatalf("handover command direction = %s, want amf_to_gnb", messageByFrame[11].Direction)
	}
	if messageByFrame[12].Direction != DirectionAMFToGNB {
		t.Fatalf("handover request direction = %s, want amf_to_gnb", messageByFrame[12].Direction)
	}
	if messageByFrame[13].Direction != DirectionGNBToAMF {
		t.Fatalf("handover request ack direction = %s, want gnb_to_amf", messageByFrame[13].Direction)
	}
}

func ngapFieldLine(frame, epoch, src, dst, procedure, pdu, amfID, ranID string) string {
	values := []string{
		frame,
		epoch,
		src,
		dst,
		"",
		"",
		procedure,
		pdu,
		amfID,
		ranID,
		"",
		"",
		"",
	}
	return strings.Join(values, "\t")
}

func findProcedureStat(t *testing.T, result *AnalysisResult, code string) ProcedureCount {
	t.Helper()
	for _, item := range result.ProcedureStats {
		if item.Code == code {
			return item
		}
	}
	t.Fatalf("procedure stat %s not found", code)
	return ProcedureCount{}
}
