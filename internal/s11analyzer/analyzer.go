package s11analyzer

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

const DefaultTimeout = 3 * time.Second

var tsharkS11Fields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ip.dst",
	"ipv6.src",
	"ipv6.dst",
	"gtpv2.message_type",
	"gtpv2.seq",
	"gtpv2.sequence_number",
	"gtpv2.teid",
	"gtpv2.cause",
	"gtpv2.apn",
	"gtpv2.f_teid_ipv4",
	"gtpv2.f_teid_ipv6",
}

type Analyzer struct {
	timeout time.Duration
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{timeout: DefaultTimeout}
}

func (a *Analyzer) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		a.timeout = timeout
	}
}

func (a *Analyzer) AnalyzeFile(ctx context.Context, pcapFile string) (*AnalysisResult, error) {
	result, err := tshark.TsharkFields(ctx, pcapFile, "gtpv2", tsharkS11Fields)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("tshark S11 analysis failed: %s", strings.TrimSpace(result.Stderr))
	}
	messages := parseFieldRows(result.Stdout)
	return a.analyze(pcapFile, messages), nil
}

func (a *Analyzer) analyze(filename string, messages []*Message) *AnalysisResult {
	sort.Slice(messages, func(i, j int) bool { return messages[i].FrameNumber < messages[j].FrameNumber })
	for i, msg := range messages {
		msg.ID = fmt.Sprintf("s11-%d", i+1)
	}
	transactions := a.analyzeTransactions(messages)
	return &AnalysisResult{
		Filename:       filename,
		AnalyzedAt:     time.Now(),
		TotalPackets:   len(messages),
		Statistics:     calculateStatistics(messages, transactions),
		Messages:       messages,
		TypeStats:      calculateTypeStats(messages),
		Transactions:   transactions,
		ProcedureStats: calculateProcedureStats(transactions),
	}
}

func parseFieldRows(output string) []*Message {
	lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
	messages := make([]*Message, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		for len(cols) < len(tsharkS11Fields) {
			cols = append(cols, "")
		}
		sourceIP := firstNonEmpty(cols[2], cols[4])
		destinationIP := firstNonEmpty(cols[3], cols[5])
		msgType := parseInt(firstValue(cols[6]))
		if msgType == 0 || net.ParseIP(sourceIP) == nil || net.ParseIP(destinationIP) == nil {
			continue
		}
		cause := firstValue(cols[10])
		msg := &Message{
			FrameNumber:     parseInt(cols[0]),
			Timestamp:       parseEpoch(cols[1]),
			SourceIP:        sourceIP,
			DestinationIP:   destinationIP,
			MessageTypeCode: msgType,
			MessageType:     MessageTypeName(msgType),
			SequenceNumber:  parseInt(firstNonEmpty(cols[7], cols[8])),
			TEID:            firstValue(cols[9]),
			Cause:           cause,
			CauseName:       CauseName(cause),
			APN:             firstValue(cols[11]),
			FTEIDIPv4:       firstValue(cols[12]),
			FTEIDIPv6:       firstValue(cols[13]),
		}
		msg.WiresharkFilter = messageFilter(msg)
		messages = append(messages, msg)
	}
	return messages
}

func (a *Analyzer) analyzeTransactions(messages []*Message) []*Transaction {
	requests := make(map[string]*Message)
	requestCounts := make(map[string][]int)
	transactions := make([]*Transaction, 0)

	for _, msg := range messages {
		if isRequest(msg.MessageTypeCode) {
			key := requestKey(msg, msg.MessageTypeCode)
			requestCounts[key] = append(requestCounts[key], msg.FrameNumber)
			if _, exists := requests[key]; !exists {
				requests[key] = msg
			}
			continue
		}
		reqType, ok := responseToRequest[msg.MessageTypeCode]
		if !ok {
			continue
		}
		key := responseKey(msg, reqType)
		req, ok := requests[key]
		if !ok {
			continue
		}
		transactions = append(transactions, a.buildTransaction(req, msg, requestCounts[key]))
		delete(requests, key)
	}

	for key, req := range requests {
		transactions = append(transactions, a.buildTransaction(req, nil, requestCounts[key]))
	}
	sort.SliceStable(transactions, func(i, j int) bool { return transactions[i].RequestFrame < transactions[j].RequestFrame })
	for i, tx := range transactions {
		tx.ID = fmt.Sprintf("s11-tx-%d", i+1)
	}
	return transactions
}

func (a *Analyzer) buildTransaction(req, resp *Message, requestFrames []int) *Transaction {
	tx := &Transaction{
		Procedure:       procedureName(req.MessageTypeCode),
		Status:          StatusNoResponse,
		SequenceNumber:  req.SequenceNumber,
		RequestFrame:    req.FrameNumber,
		RequestTime:     req.Timestamp,
		RequestType:     req.MessageType,
		SourceIP:        req.SourceIP,
		DestinationIP:   req.DestinationIP,
		RequestTEID:     req.TEID,
		APN:             req.APN,
		FTEIDIPv4:       req.FTEIDIPv4,
		WiresharkFilter: fmt.Sprintf("gtpv2.seq == %d && %s && %s", req.SequenceNumber, addressFilter(req.SourceIP), addressFilter(req.DestinationIP)),
	}
	if len(requestFrames) > 1 {
		tx.RetransmitCount = len(requestFrames) - 1
		tx.RetransmitFrames = append([]int(nil), requestFrames[1:]...)
	}
	if resp == nil {
		if tx.RetransmitCount > 0 {
			tx.Status = StatusRetransmit
		}
		return tx
	}
	tx.ResponseFrame = resp.FrameNumber
	tx.ResponseTime = resp.Timestamp
	tx.ResponseTimeMs = resp.Timestamp.Sub(req.Timestamp).Seconds() * 1000
	tx.ResponseType = resp.MessageType
	tx.Cause = resp.Cause
	tx.CauseName = resp.CauseName
	tx.ResponseTEID = resp.TEID
	if tx.APN == "" {
		tx.APN = resp.APN
	}
	if tx.FTEIDIPv4 == "" {
		tx.FTEIDIPv4 = resp.FTEIDIPv4
	}
	if isAcceptedCause(resp.Cause) {
		if resp.Timestamp.Sub(req.Timestamp) > a.timeout {
			tx.Status = StatusTimeout
		} else {
			tx.Status = StatusSuccess
		}
	} else {
		tx.Status = StatusFailed
	}
	tx.WiresharkFilter = fmt.Sprintf("gtpv2.seq == %d && (%s) && (%s)", req.SequenceNumber, addressFilter(req.SourceIP), addressFilter(req.DestinationIP))
	return tx
}

var requestToResponse = map[int]int{
	32: 33, 34: 35, 36: 37, 38: 39, 95: 96, 97: 98, 99: 100,
	101: 102, 160: 161, 170: 171, 179: 180, 211: 212,
}

var responseToRequest = reverseMap(requestToResponse)

func reverseMap(input map[int]int) map[int]int {
	out := make(map[int]int, len(input))
	for req, resp := range input {
		out[resp] = req
	}
	return out
}

func isRequest(code int) bool {
	_, ok := requestToResponse[code]
	return ok
}

func requestKey(msg *Message, requestType int) string {
	return fmt.Sprintf("%d:%d:%s:%s", requestType, msg.SequenceNumber, msg.SourceIP, msg.DestinationIP)
}

func responseKey(msg *Message, requestType int) string {
	return fmt.Sprintf("%d:%d:%s:%s", requestType, msg.SequenceNumber, msg.DestinationIP, msg.SourceIP)
}

func procedureName(requestType int) string {
	name := MessageTypeName(requestType)
	return strings.TrimSuffix(strings.TrimSuffix(name, " Request"), " Notification")
}

func isAcceptedCause(cause string) bool {
	cause = firstToken(cause)
	return cause == "" || cause == "16" || cause == "17"
}

func calculateStatistics(messages []*Message, transactions []*Transaction) Statistics {
	stats := Statistics{TotalMessages: len(messages), TotalTransactions: len(transactions), MinResponseTimeMs: -1}
	var totalResponse float64
	var responseCount int
	for _, msg := range messages {
		if isRequest(msg.MessageTypeCode) {
			stats.Requests++
		} else if _, ok := responseToRequest[msg.MessageTypeCode]; ok {
			stats.Responses++
		}
	}
	for _, tx := range transactions {
		switch tx.Status {
		case StatusSuccess:
			stats.Successful++
		case StatusFailed:
			stats.Failed++
		case StatusNoResponse:
			stats.NoResponse++
		case StatusTimeout:
			stats.Timeout++
		case StatusRetransmit:
			stats.Retransmit += tx.RetransmitCount
		}
		if tx.Status != StatusRetransmit {
			stats.Retransmit += tx.RetransmitCount
		}
		switch tx.Procedure {
		case "Create Session":
			stats.CreateSession++
		case "Modify Bearer":
			stats.ModifyBearer++
		case "Delete Session":
			stats.DeleteSession++
		default:
			if strings.Contains(tx.Procedure, "Bearer") {
				stats.BearerOperations++
			}
		}
		if tx.ResponseTimeMs > 0 {
			totalResponse += tx.ResponseTimeMs
			responseCount++
			if stats.MinResponseTimeMs < 0 || tx.ResponseTimeMs < stats.MinResponseTimeMs {
				stats.MinResponseTimeMs = tx.ResponseTimeMs
			}
			if tx.ResponseTimeMs > stats.MaxResponseTimeMs {
				stats.MaxResponseTimeMs = tx.ResponseTimeMs
			}
		}
	}
	if stats.TotalTransactions > 0 {
		stats.SuccessRate = float64(stats.Successful) / float64(stats.TotalTransactions) * 100
	}
	if responseCount > 0 {
		stats.AvgResponseTimeMs = totalResponse / float64(responseCount)
	}
	if stats.MinResponseTimeMs < 0 {
		stats.MinResponseTimeMs = 0
	}
	return stats
}

func calculateTypeStats(messages []*Message) []TypeCount {
	byCode := make(map[int]*TypeCount)
	for _, msg := range messages {
		if _, ok := byCode[msg.MessageTypeCode]; !ok {
			byCode[msg.MessageTypeCode] = &TypeCount{Code: msg.MessageTypeCode, Name: msg.MessageType}
		}
		byCode[msg.MessageTypeCode].Count++
	}
	out := make([]TypeCount, 0, len(byCode))
	for _, item := range byCode {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Code < out[j].Code
	})
	return out
}

func calculateProcedureStats(transactions []*Transaction) []ProcedureCount {
	byName := make(map[string]*ProcedureCount)
	for _, tx := range transactions {
		if _, ok := byName[tx.Procedure]; !ok {
			byName[tx.Procedure] = &ProcedureCount{Name: tx.Procedure}
		}
		byName[tx.Procedure].Count++
	}
	out := make([]ProcedureCount, 0, len(byName))
	for _, item := range byName {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func messageFilter(msg *Message) string {
	return fmt.Sprintf("frame.number == %d && gtpv2.message_type == %d", msg.FrameNumber, msg.MessageTypeCode)
}

func addressFilter(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("ipv6.addr == %s", ip)
	}
	return fmt.Sprintf("ip.addr == %s", ip)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = firstValue(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func firstValue(field string) string {
	values := splitValues(field)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func splitValues(field string) []string {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil
	}
	raw := strings.FieldsFunc(field, func(r rune) bool { return r == ',' || r == ';' })
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		value = firstToken(value)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func firstToken(value string) string {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if idx := strings.IndexAny(value, " \t("); idx >= 0 {
		value = value[:idx]
	}
	return value
}

func parseInt(value string) int {
	value = firstToken(value)
	if value == "" {
		return 0
	}
	if parsed, err := strconv.ParseInt(value, 0, 64); err == nil {
		return int(parsed)
	}
	if parsed, err := strconv.ParseInt(value, 16, 64); err == nil {
		return int(parsed)
	}
	return 0
}

func parseEpoch(value string) time.Time {
	value = firstToken(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return time.Time{}
	}
	sec := int64(parsed)
	nsec := int64((parsed - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}
