package api

import (
	"math"
	"sort"
	"strings"

	"gitee.com/yangdadayyds/uepcap/internal/nasanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/ngapanalyzer"
	"gitee.com/yangdadayyds/uepcap/internal/pfcpsession"
	"gitee.com/yangdadayyds/uepcap/internal/s11analyzer"
	"gitee.com/yangdadayyds/uepcap/internal/s1apanalyzer"
)

const (
	defaultAnalysisListLimit = 500
	maxAnalysisListLimit     = 20000
)

type AnalysisWindow struct {
	Limit int `json:"limit"`
}

func normalizedAnalysisLimit(limit int) int {
	if limit <= 0 {
		return defaultAnalysisListLimit
	}
	if limit > maxAnalysisListLimit {
		return maxAnalysisListLimit
	}
	return limit
}

func windowPFCPAnalysis(result *pfcpsession.AnalysisResult, limit int, responseTimeFilter string) pfcpsession.AnalysisResult {
	out := *result
	out.Transactions = append([]*pfcpsession.Transaction(nil), result.Transactions...)
	sortPFCPTransactions(out.Transactions, responseTimeFilter)
	if len(out.Transactions) > limit {
		out.Transactions = out.Transactions[:limit]
	}
	out.Transactions = appendMissingPFCPAttentionTransactions(out.Transactions, result.Transactions)
	out.Transactions = appendMissingPFCPResponseExtremes(out.Transactions, result.Transactions, result.Statistics.MinResponseTimeMs, result.Statistics.MaxResponseTimeMs)
	if out.Transactions == nil {
		out.Transactions = []*pfcpsession.Transaction{}
	}
	return out
}

func sortPFCPTransactions(transactions []*pfcpsession.Transaction, responseTimeFilter string) {
	sort.SliceStable(transactions, func(i, j int) bool {
		left := pfcpResponseTimeForSort(transactions[i])
		right := pfcpResponseTimeForSort(transactions[j])
		if responseTimeFilter == "min" {
			if left != right {
				return left < right
			}
		} else if left != right {
			return left > right
		}
		return transactions[i].RequestFrame < transactions[j].RequestFrame
	})
}

func pfcpResponseTimeForSort(tx *pfcpsession.Transaction) float64 {
	if tx == nil || tx.ResponseTimeMs == nil {
		return math.Inf(-1)
	}
	return *tx.ResponseTimeMs
}

func appendMissingPFCPAttentionTransactions(window, all []*pfcpsession.Transaction) []*pfcpsession.Transaction {
	present := make(map[*pfcpsession.Transaction]bool, len(window))
	for _, tx := range window {
		if tx != nil {
			present[tx] = true
		}
	}
	for _, tx := range all {
		if tx == nil || present[tx] || !isPFCPAttentionTransaction(tx) {
			continue
		}
		window = append(window, tx)
		present[tx] = true
	}
	return window
}

func isPFCPAttentionTransaction(tx *pfcpsession.Transaction) bool {
	switch tx.Status {
	case pfcpsession.StatusFailed, pfcpsession.StatusNoResponse, pfcpsession.StatusTimeout:
		return true
	default:
		return tx.RetransmitCount > 0
	}
}

func appendMissingPFCPResponseExtremes(window, all []*pfcpsession.Transaction, minResponseTime, maxResponseTime float64) []*pfcpsession.Transaction {
	for _, target := range []float64{maxResponseTime, minResponseTime} {
		if target <= 0 || containsPFCPResponseTime(window, target) {
			continue
		}
		for _, tx := range all {
			if tx != nil && tx.ResponseTimeMs != nil && sameFloat(*tx.ResponseTimeMs, target) {
				window = append(window, tx)
				break
			}
		}
	}
	return window
}

func containsPFCPResponseTime(transactions []*pfcpsession.Transaction, target float64) bool {
	for _, tx := range transactions {
		if tx != nil && tx.ResponseTimeMs != nil && sameFloat(*tx.ResponseTimeMs, target) {
			return true
		}
	}
	return false
}

func windowS11Analysis(result *s11analyzer.AnalysisResult, limit int, responseTimeFilter string) s11analyzer.AnalysisResult {
	out := *result
	out.Transactions = append([]*s11analyzer.Transaction(nil), result.Transactions...)
	sortS11Transactions(out.Transactions, responseTimeFilter)
	if len(out.Transactions) > limit {
		out.Transactions = out.Transactions[:limit]
	}
	out.Transactions = appendMissingS11AttentionTransactions(out.Transactions, result.Transactions)
	out.Transactions = appendMissingS11ResponseExtremes(out.Transactions, result.Transactions, result.Statistics.MinResponseTimeMs, result.Statistics.MaxResponseTimeMs)
	if out.Transactions == nil {
		out.Transactions = []*s11analyzer.Transaction{}
	}
	if out.ProcedureStats == nil {
		out.ProcedureStats = []s11analyzer.ProcedureCount{}
	}
	if out.TypeStats == nil {
		out.TypeStats = []s11analyzer.TypeCount{}
	}
	out.Messages = []*s11analyzer.Message{}
	return out
}

func appendMissingS11AttentionTransactions(window, all []*s11analyzer.Transaction) []*s11analyzer.Transaction {
	present := make(map[*s11analyzer.Transaction]bool, len(window))
	for _, tx := range window {
		if tx != nil {
			present[tx] = true
		}
	}
	for _, tx := range all {
		if tx == nil || present[tx] || !isS11AttentionTransaction(tx) {
			continue
		}
		window = append(window, tx)
		present[tx] = true
	}
	return window
}

func isS11AttentionTransaction(tx *s11analyzer.Transaction) bool {
	switch tx.Status {
	case s11analyzer.StatusFailed, s11analyzer.StatusNoResponse, s11analyzer.StatusTimeout:
		return true
	default:
		return tx.RetransmitCount > 0
	}
}

func sortS11Transactions(transactions []*s11analyzer.Transaction, responseTimeFilter string) {
	sort.SliceStable(transactions, func(i, j int) bool {
		left := s11ResponseTimeForSort(transactions[i])
		right := s11ResponseTimeForSort(transactions[j])
		if responseTimeFilter == "min" {
			if left != right {
				return left < right
			}
		} else if left != right {
			return left > right
		}
		return transactions[i].RequestFrame < transactions[j].RequestFrame
	})
}

func s11ResponseTimeForSort(tx *s11analyzer.Transaction) float64 {
	if tx == nil || tx.ResponseFrame == 0 {
		return math.Inf(-1)
	}
	return tx.ResponseTimeMs
}

func appendMissingS11ResponseExtremes(window, all []*s11analyzer.Transaction, minResponseTime, maxResponseTime float64) []*s11analyzer.Transaction {
	for _, target := range []float64{maxResponseTime, minResponseTime} {
		if target <= 0 || containsS11ResponseTime(window, target) {
			continue
		}
		for _, tx := range all {
			if tx != nil && tx.ResponseFrame != 0 && sameFloat(tx.ResponseTimeMs, target) {
				window = append(window, tx)
				break
			}
		}
	}
	return window
}

func containsS11ResponseTime(transactions []*s11analyzer.Transaction, target float64) bool {
	for _, tx := range transactions {
		if tx != nil && tx.ResponseFrame != 0 && sameFloat(tx.ResponseTimeMs, target) {
			return true
		}
	}
	return false
}

func sameFloat(left, right float64) bool {
	return math.Abs(left-right) < 0.000001
}

func windowNASAnalysis(result *nasanalyzer.AnalysisResult, limit int) nasanalyzer.AnalysisResult {
	out := *result
	flows := append([]*nasanalyzer.Flow(nil), result.Flows...)
	sort.SliceStable(flows, func(i, j int) bool {
		left := nasFlowDurationForSort(flows[i])
		right := nasFlowDurationForSort(flows[j])
		if left != right {
			return left > right
		}
		return flows[i].StartFrame < flows[j].StartFrame
	})
	if len(result.Flows) > limit {
		out.Flows = append([]*nasanalyzer.Flow(nil), flows[:limit]...)
	} else {
		out.Flows = flows
	}
	if len(result.Messages) > limit {
		out.Messages = append([]*nasanalyzer.Message(nil), result.Messages[:limit]...)
	} else {
		out.Messages = append([]*nasanalyzer.Message(nil), result.Messages...)
	}
	if out.Flows == nil {
		out.Flows = []*nasanalyzer.Flow{}
	}
	if out.Messages == nil {
		out.Messages = []*nasanalyzer.Message{}
	}
	if out.TypeStats == nil {
		out.TypeStats = []nasanalyzer.TypeCount{}
	}
	return out
}

func nasFlowDurationForSort(flow *nasanalyzer.Flow) float64 {
	if flow == nil {
		return math.Inf(-1)
	}
	return flow.DurationMs
}

func windowNGAPAnalysis(result *ngapanalyzer.AnalysisResult, limit int, procedureFilter string) ngapanalyzer.AnalysisResult {
	out := *result
	procedureFilter = normalizedProcedureFilter(procedureFilter)
	sourceTransactions := filterNGAPTransactions(result.Transactions, procedureFilter)
	transactions := append([]*ngapanalyzer.Transaction(nil), sourceTransactions...)
	sort.SliceStable(transactions, func(i, j int) bool {
		left := ngapTransactionDurationForSort(transactions[i])
		right := ngapTransactionDurationForSort(transactions[j])
		if left != right {
			return left > right
		}
		return transactions[i].StartFrame < transactions[j].StartFrame
	})
	if len(transactions) > limit {
		out.Transactions = append([]*ngapanalyzer.Transaction(nil), transactions[:limit]...)
	} else {
		out.Transactions = transactions
	}
	out.Transactions = appendMissingNGAPAttentionTransactions(out.Transactions, sourceTransactions)
	sourceMessages := filterNGAPMessages(result.Messages, procedureFilter)
	if len(sourceMessages) > limit {
		out.Messages = append([]*ngapanalyzer.Message(nil), sourceMessages[:limit]...)
	} else {
		out.Messages = append([]*ngapanalyzer.Message(nil), sourceMessages...)
	}
	if out.Transactions == nil {
		out.Transactions = []*ngapanalyzer.Transaction{}
	}
	if out.Messages == nil {
		out.Messages = []*ngapanalyzer.Message{}
	}
	if out.ProcedureStats == nil {
		out.ProcedureStats = []ngapanalyzer.ProcedureCount{}
	}
	return out
}

func ngapTransactionDurationForSort(tx *ngapanalyzer.Transaction) float64 {
	if tx == nil {
		return math.Inf(-1)
	}
	return tx.DurationMs
}

func filterNGAPTransactions(transactions []*ngapanalyzer.Transaction, procedureFilter string) []*ngapanalyzer.Transaction {
	if procedureFilter == "" {
		return transactions
	}
	filtered := make([]*ngapanalyzer.Transaction, 0)
	for _, tx := range transactions {
		if tx != nil && tx.ProcedureCode == procedureFilter {
			filtered = append(filtered, tx)
		}
	}
	return filtered
}

func filterNGAPMessages(messages []*ngapanalyzer.Message, procedureFilter string) []*ngapanalyzer.Message {
	if procedureFilter == "" {
		return messages
	}
	filtered := make([]*ngapanalyzer.Message, 0)
	for _, msg := range messages {
		if msg != nil && msg.ProcedureCode == procedureFilter {
			filtered = append(filtered, msg)
		}
	}
	return filtered
}

func appendMissingNGAPAttentionTransactions(window, all []*ngapanalyzer.Transaction) []*ngapanalyzer.Transaction {
	present := make(map[*ngapanalyzer.Transaction]bool, len(window))
	for _, tx := range window {
		if tx != nil {
			present[tx] = true
		}
	}
	for _, tx := range all {
		if tx == nil || present[tx] || !isNGAPAttentionTransaction(tx) {
			continue
		}
		window = append(window, tx)
		present[tx] = true
	}
	return window
}

func isNGAPAttentionTransaction(tx *ngapanalyzer.Transaction) bool {
	switch tx.Status {
	case ngapanalyzer.TransactionFailed, ngapanalyzer.TransactionInProgress:
		return true
	default:
		return false
	}
}

func windowS1APAnalysis(result *s1apanalyzer.AnalysisResult, limit int, procedureFilter string) s1apanalyzer.AnalysisResult {
	out := *result
	procedureFilter = normalizedProcedureFilter(procedureFilter)
	sourceTransactions := filterS1APTransactions(result.Transactions, procedureFilter)
	transactions := append([]*s1apanalyzer.Transaction(nil), sourceTransactions...)
	sort.SliceStable(transactions, func(i, j int) bool {
		left := s1apTransactionDurationForSort(transactions[i])
		right := s1apTransactionDurationForSort(transactions[j])
		if left != right {
			return left > right
		}
		return transactions[i].StartFrame < transactions[j].StartFrame
	})
	if len(transactions) > limit {
		out.Transactions = append([]*s1apanalyzer.Transaction(nil), transactions[:limit]...)
	} else {
		out.Transactions = transactions
	}
	out.Transactions = appendMissingS1APAttentionTransactions(out.Transactions, sourceTransactions)
	sourceMessages := filterS1APMessages(result.Messages, procedureFilter)
	if len(sourceMessages) > limit {
		out.Messages = append([]*s1apanalyzer.Message(nil), sourceMessages[:limit]...)
	} else {
		out.Messages = append([]*s1apanalyzer.Message(nil), sourceMessages...)
	}
	if out.Transactions == nil {
		out.Transactions = []*s1apanalyzer.Transaction{}
	}
	if out.Messages == nil {
		out.Messages = []*s1apanalyzer.Message{}
	}
	if out.ProcedureStats == nil {
		out.ProcedureStats = []s1apanalyzer.ProcedureCount{}
	}
	return out
}

func s1apTransactionDurationForSort(tx *s1apanalyzer.Transaction) float64 {
	if tx == nil {
		return math.Inf(-1)
	}
	return tx.DurationMs
}

func filterS1APTransactions(transactions []*s1apanalyzer.Transaction, procedureFilter string) []*s1apanalyzer.Transaction {
	if procedureFilter == "" {
		return transactions
	}
	filtered := make([]*s1apanalyzer.Transaction, 0)
	for _, tx := range transactions {
		if tx != nil && tx.ProcedureCode == procedureFilter {
			filtered = append(filtered, tx)
		}
	}
	return filtered
}

func filterS1APMessages(messages []*s1apanalyzer.Message, procedureFilter string) []*s1apanalyzer.Message {
	if procedureFilter == "" {
		return messages
	}
	filtered := make([]*s1apanalyzer.Message, 0)
	for _, msg := range messages {
		if msg != nil && msg.ProcedureCode == procedureFilter {
			filtered = append(filtered, msg)
		}
	}
	return filtered
}

func appendMissingS1APAttentionTransactions(window, all []*s1apanalyzer.Transaction) []*s1apanalyzer.Transaction {
	present := make(map[*s1apanalyzer.Transaction]bool, len(window))
	for _, tx := range window {
		if tx != nil {
			present[tx] = true
		}
	}
	for _, tx := range all {
		if tx == nil || present[tx] || !isS1APAttentionTransaction(tx) {
			continue
		}
		window = append(window, tx)
		present[tx] = true
	}
	return window
}

func isS1APAttentionTransaction(tx *s1apanalyzer.Transaction) bool {
	switch tx.Status {
	case s1apanalyzer.TransactionFailed, s1apanalyzer.TransactionInProgress:
		return true
	default:
		return false
	}
}

func normalizedProcedureFilter(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "all") {
		return ""
	}
	return value
}
