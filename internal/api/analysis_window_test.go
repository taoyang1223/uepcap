package api

import (
	"testing"

	"gitee.com/yangdadayyds/uepcap/internal/ngapanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
	"gitee.com/yangdadayyds/uepcap/internal/s11analyzer"
	"gitee.com/yangdadayyds/uepcap/internal/s1apanalyzer"
)

func TestWindowPFCPAnalysisKeepsAttentionTransactions(t *testing.T) {
	responseTime := 12.0
	result := &pfcpsession.AnalysisResult{
		Statistics: pfcpsession.Statistics{
			MinResponseTimeMs: responseTime,
			MaxResponseTimeMs: responseTime,
		},
		Transactions: []*pfcpsession.Transaction{
			{
				ID:             "success",
				RequestFrame:   1,
				Status:         pfcpsession.StatusSuccess,
				ResponseTimeMs: &responseTime,
			},
			{
				ID:           "no-response",
				RequestFrame: 2,
				Status:       pfcpsession.StatusNoResponse,
			},
			{
				ID:           "failed",
				RequestFrame: 3,
				Status:       pfcpsession.StatusFailed,
			},
			{
				ID:           "timeout",
				RequestFrame: 4,
				Status:       pfcpsession.StatusTimeout,
			},
			{
				ID:              "retransmit",
				RequestFrame:    5,
				Status:          pfcpsession.StatusSuccess,
				RetransmitCount: 1,
			},
		},
	}

	window := windowPFCPAnalysis(result, 1, "")

	if !containsPFCPTransactionID(window.Transactions, "no-response") {
		t.Fatalf("window does not include no-response transaction")
	}
	if !containsPFCPTransactionID(window.Transactions, "failed") {
		t.Fatalf("window does not include failed transaction")
	}
	if !containsPFCPTransactionID(window.Transactions, "timeout") {
		t.Fatalf("window does not include timeout transaction")
	}
	if !containsPFCPTransactionID(window.Transactions, "retransmit") {
		t.Fatalf("window does not include retransmit transaction")
	}
}

func containsPFCPTransactionID(transactions []*pfcpsession.Transaction, id string) bool {
	for _, tx := range transactions {
		if tx != nil && tx.ID == id {
			return true
		}
	}
	return false
}

func TestWindowS11AnalysisKeepsAttentionTransactions(t *testing.T) {
	result := &s11analyzer.AnalysisResult{
		Transactions: []*s11analyzer.Transaction{
			{
				ID:             "success",
				RequestFrame:   1,
				Status:         s11analyzer.StatusSuccess,
				ResponseFrame:  10,
				ResponseTimeMs: 12,
			},
			{
				ID:           "no-response",
				RequestFrame: 2,
				Status:       s11analyzer.StatusNoResponse,
			},
			{
				ID:           "failed",
				RequestFrame: 3,
				Status:       s11analyzer.StatusFailed,
			},
			{
				ID:           "timeout",
				RequestFrame: 4,
				Status:       s11analyzer.StatusTimeout,
			},
			{
				ID:              "retransmit",
				RequestFrame:    5,
				Status:          s11analyzer.StatusSuccess,
				RetransmitCount: 1,
			},
		},
	}

	window := windowS11Analysis(result, 1, "")

	if !containsS11TransactionID(window.Transactions, "no-response") {
		t.Fatalf("window does not include no-response transaction")
	}
	if !containsS11TransactionID(window.Transactions, "failed") {
		t.Fatalf("window does not include failed transaction")
	}
	if !containsS11TransactionID(window.Transactions, "timeout") {
		t.Fatalf("window does not include timeout transaction")
	}
	if !containsS11TransactionID(window.Transactions, "retransmit") {
		t.Fatalf("window does not include retransmit transaction")
	}
}

func containsS11TransactionID(transactions []*s11analyzer.Transaction, id string) bool {
	for _, tx := range transactions {
		if tx != nil && tx.ID == id {
			return true
		}
	}
	return false
}

func TestWindowNGAPAnalysisKeepsAttentionTransactions(t *testing.T) {
	result := &ngapanalyzer.AnalysisResult{
		Transactions: []*ngapanalyzer.Transaction{
			{
				ID:         "success",
				StartFrame: 1,
				Status:     ngapanalyzer.TransactionSuccess,
				DurationMs: 12,
			},
			{
				ID:         "failed",
				StartFrame: 2,
				Status:     ngapanalyzer.TransactionFailed,
			},
			{
				ID:         "in-progress",
				StartFrame: 3,
				Status:     ngapanalyzer.TransactionInProgress,
			},
		},
	}

	window := windowNGAPAnalysis(result, 1, "")

	if !containsNGAPTransactionID(window.Transactions, "failed") {
		t.Fatalf("window does not include failed transaction")
	}
	if !containsNGAPTransactionID(window.Transactions, "in-progress") {
		t.Fatalf("window does not include in-progress transaction")
	}
}

func containsNGAPTransactionID(transactions []*ngapanalyzer.Transaction, id string) bool {
	for _, tx := range transactions {
		if tx != nil && tx.ID == id {
			return true
		}
	}
	return false
}

func TestWindowNGAPAnalysisAppliesProcedureFilterBeforeLimit(t *testing.T) {
	result := &ngapanalyzer.AnalysisResult{
		Messages: []*ngapanalyzer.Message{
			{ID: "initial-ue", FrameNumber: 1, ProcedureCode: "15"},
			{ID: "paging", FrameNumber: 2, ProcedureCode: "24"},
		},
		Transactions: []*ngapanalyzer.Transaction{
			{ID: "setup", StartFrame: 1, ProcedureCode: "29", Status: ngapanalyzer.TransactionSuccess},
			{ID: "release", StartFrame: 2, ProcedureCode: "41", Status: ngapanalyzer.TransactionInProgress},
		},
	}

	window := windowNGAPAnalysis(result, 1, "24")

	if len(window.Messages) != 1 || window.Messages[0].ID != "paging" {
		t.Fatalf("window messages = %#v, want only paging", window.Messages)
	}
	if len(window.Transactions) != 0 {
		t.Fatalf("window transactions = %#v, want no transactions for procedure 24", window.Transactions)
	}
}

func TestWindowS1APAnalysisKeepsAttentionTransactions(t *testing.T) {
	result := &s1apanalyzer.AnalysisResult{
		Transactions: []*s1apanalyzer.Transaction{
			{
				ID:         "success",
				StartFrame: 1,
				Status:     s1apanalyzer.TransactionSuccess,
				DurationMs: 12,
			},
			{
				ID:         "failed",
				StartFrame: 2,
				Status:     s1apanalyzer.TransactionFailed,
			},
			{
				ID:         "in-progress",
				StartFrame: 3,
				Status:     s1apanalyzer.TransactionInProgress,
			},
		},
	}

	window := windowS1APAnalysis(result, 1, "")

	if !containsS1APTransactionID(window.Transactions, "failed") {
		t.Fatalf("window does not include failed transaction")
	}
	if !containsS1APTransactionID(window.Transactions, "in-progress") {
		t.Fatalf("window does not include in-progress transaction")
	}
}

func containsS1APTransactionID(transactions []*s1apanalyzer.Transaction, id string) bool {
	for _, tx := range transactions {
		if tx != nil && tx.ID == id {
			return true
		}
	}
	return false
}

func TestWindowS1APAnalysisAppliesProcedureFilterBeforeLimit(t *testing.T) {
	result := &s1apanalyzer.AnalysisResult{
		Messages: []*s1apanalyzer.Message{
			{ID: "initial-ue", FrameNumber: 1, ProcedureCode: "12"},
			{ID: "paging", FrameNumber: 2, ProcedureCode: "10"},
		},
		Transactions: []*s1apanalyzer.Transaction{
			{ID: "setup", StartFrame: 1, ProcedureCode: "17", Status: s1apanalyzer.TransactionSuccess},
			{ID: "release", StartFrame: 2, ProcedureCode: "23", Status: s1apanalyzer.TransactionInProgress},
		},
	}

	window := windowS1APAnalysis(result, 1, "10")

	if len(window.Messages) != 1 || window.Messages[0].ID != "paging" {
		t.Fatalf("window messages = %#v, want only paging", window.Messages)
	}
	if len(window.Transactions) != 0 {
		t.Fatalf("window transactions = %#v, want no transactions for procedure 10", window.Transactions)
	}
}
