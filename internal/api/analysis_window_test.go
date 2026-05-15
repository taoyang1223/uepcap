package api

import (
	"testing"

	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
	"gitee.com/yangdadayyds/uepcap/internal/s11analyzer"
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
