package pfcpsession

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

var tsharkSessionFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ip.dst",
	"ipv6.src",
	"ipv6.dst",
	"udp.srcport",
	"udp.dstport",
	"pfcp.msg_type",
	"pfcp.seid",
	"pfcp.seqno",
	"pfcp.cause",
	"pfcp.f_seid.ipv4",
	"pfcp.f_seid.ipv6",
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
	result, err := tshark.TsharkFields(ctx, pcapFile, "pfcp.msg_type >= 50 && pfcp.msg_type <= 55", tsharkSessionFields)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("tshark PFCP session analysis failed: %s", strings.TrimSpace(result.Stderr))
	}

	messages := parseFieldRows(result.Stdout)
	return a.analyze(pcapFile, messages), nil
}

func (a *Analyzer) analyze(filename string, messages []*Message) *AnalysisResult {
	result := &AnalysisResult{
		Filename:     filename,
		AnalyzedAt:   time.Now(),
		TotalPackets: len(messages),
	}

	requests := make(map[string]*Message)
	responses := make(map[string]*Message)
	requestCounts := make(map[string][]int)

	for _, msg := range messages {
		if !isSessionMessage(msg.MessageTypeCode) {
			continue
		}

		key := makeKey(msg)
		if isRequest(msg.MessageTypeCode) {
			requestCounts[key] = append(requestCounts[key], msg.FrameNumber)
			if _, exists := requests[key]; !exists {
				requests[key] = msg
			}
			continue
		}
		if isResponse(msg.MessageTypeCode) {
			reverseKey := makeReverseKey(msg)
			if _, exists := responses[reverseKey]; !exists {
				responses[reverseKey] = msg
			}
		}
	}

	transactions := make([]*Transaction, 0, len(requests))
	txID := 0
	for key, req := range requests {
		txID++
		tx := &Transaction{
			ID:              fmt.Sprintf("tx-%d", txID),
			RequestSEID:     req.HeaderSEID,
			RequestFSEID:    req.FSEID,
			SequenceNumber:  req.SequenceNumber,
			MessageType:     messageTypeCategory(req.MessageTypeCode),
			MessageTypeCode: req.MessageTypeCode,
			SourceIP:        req.SourceIP,
			DestinationIP:   req.DestinationIP,
			RequestTime:     req.Timestamp,
			RequestFrame:    req.FrameNumber,
			WiresharkFilter: transactionFilter(req),
		}

		if frames := requestCounts[key]; len(frames) > 1 {
			tx.RetransmitCount = len(frames) - 1
			tx.RetransmitFrames = append([]int(nil), frames[1:]...)
		}

		if resp, ok := responses[key]; ok {
			tx.ResponseSEID = resp.HeaderSEID
			tx.ResponseFSEID = resp.FSEID
			tx.ResponseTime = &resp.Timestamp
			tx.ResponseFrame = &resp.FrameNumber

			responseTimeMs := resp.Timestamp.Sub(req.Timestamp).Seconds() * 1000
			tx.ResponseTimeMs = &responseTimeMs

			if resp.Cause != nil {
				tx.Cause = resp.Cause
				tx.CauseName = CauseName(*resp.Cause)
				if *resp.Cause == CauseRequestAccepted {
					if resp.Timestamp.Sub(req.Timestamp) > a.timeout {
						tx.Status = StatusTimeout
					} else {
						tx.Status = StatusSuccess
					}
				} else {
					tx.Status = StatusFailed
				}
			} else {
				tx.Status = StatusSuccess
			}
		} else {
			tx.Status = StatusNoResponse
		}

		if tx.RetransmitCount > 0 && tx.Status == StatusNoResponse {
			tx.Status = StatusRetransmit
		}

		transactions = append(transactions, tx)
	}

	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].RequestTime.Before(transactions[j].RequestTime)
	})
	for i, tx := range transactions {
		tx.ID = fmt.Sprintf("tx-%d", i+1)
	}

	result.Transactions = transactions
	result.Statistics = calculateStatistics(transactions)
	return result
}

func parseFieldRows(output string) []*Message {
	lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
	messages := make([]*Message, 0, len(lines))

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		cols := strings.Split(line, "\t")
		for len(cols) < len(tsharkSessionFields) {
			cols = append(cols, "")
		}

		msg := &Message{
			FrameNumber:     parseInt(cols[0]),
			Timestamp:       parseEpoch(cols[1]),
			SourceIP:        firstNonEmpty(cols[2], cols[4]),
			DestinationIP:   firstNonEmpty(cols[3], cols[5]),
			SourcePort:      uint16(parseInt(cols[6])),
			DestinationPort: uint16(parseInt(cols[7])),
			MessageTypeCode: uint8(parseInt(firstValue(cols[8]))),
			SequenceNumber:  uint32(parseInt(firstValue(cols[10]))),
			FSEIDIPv4:       firstValue(cols[12]),
			FSEIDIPv6:       firstValue(cols[13]),
		}

		seids := parseUintValues(cols[9])
		if len(seids) > 0 {
			msg.HeaderSEID = seids[0]
			msg.FSEID = seids[len(seids)-1]
		}
		if cause := firstValue(cols[11]); cause != "" {
			causeVal := uint8(parseInt(cause))
			msg.Cause = &causeVal
		}

		if msg.MessageTypeCode != 0 && net.ParseIP(msg.SourceIP) != nil && net.ParseIP(msg.DestinationIP) != nil {
			messages = append(messages, msg)
		}
	}

	return messages
}

func makeKey(msg *Message) string {
	return fmt.Sprintf("%s:%s:%d:%s", msg.SourceIP, msg.DestinationIP, msg.SequenceNumber, messageTypeCategory(msg.MessageTypeCode))
}

func makeReverseKey(msg *Message) string {
	return fmt.Sprintf("%s:%s:%d:%s", msg.DestinationIP, msg.SourceIP, msg.SequenceNumber, messageTypeCategory(msg.MessageTypeCode))
}

func transactionFilter(msg *Message) string {
	parts := []string{
		fmt.Sprintf("pfcp.seqno == %d", msg.SequenceNumber),
		addressFilter(msg.SourceIP),
		addressFilter(msg.DestinationIP),
	}
	if msg.HeaderSEID != 0 {
		parts = append(parts, fmt.Sprintf("pfcp.seid == %d", msg.HeaderSEID))
	}
	return strings.Join(parts, " && ")
}

func addressFilter(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("ipv6.addr == %s", ip)
	}
	return fmt.Sprintf("ip.addr == %s", ip)
}

func calculateStatistics(transactions []*Transaction) Statistics {
	stats := Statistics{TotalTransactions: len(transactions), MinResponseTimeMs: -1}
	var responseTotal float64
	var responseCount int

	for _, tx := range transactions {
		switch tx.Status {
		case StatusSuccess:
			stats.Success++
		case StatusFailed:
			stats.Failed++
		case StatusNoResponse:
			stats.NoResponse++
		case StatusTimeout:
			stats.Timeout++
		}

		stats.Retransmit += tx.RetransmitCount

		switch tx.MessageType {
		case "Session Establishment":
			stats.SessionEstablishment++
		case "Session Modification":
			stats.SessionModification++
		case "Session Deletion":
			stats.SessionDeletion++
		}

		if tx.ResponseTimeMs != nil {
			responseTotal += *tx.ResponseTimeMs
			responseCount++
			if stats.MinResponseTimeMs < 0 || *tx.ResponseTimeMs < stats.MinResponseTimeMs {
				stats.MinResponseTimeMs = *tx.ResponseTimeMs
			}
			if *tx.ResponseTimeMs > stats.MaxResponseTimeMs {
				stats.MaxResponseTimeMs = *tx.ResponseTimeMs
			}
		}
	}

	if responseCount > 0 {
		stats.AvgResponseTimeMs = responseTotal / float64(responseCount)
	}
	if stats.MinResponseTimeMs < 0 {
		stats.MinResponseTimeMs = 0
	}

	return stats
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
	raw := strings.FieldsFunc(field, func(r rune) bool {
		return r == ',' || r == ';'
	})
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func parseUintValues(field string) []uint64 {
	raw := splitValues(field)
	values := make([]uint64, 0, len(raw))
	for _, value := range raw {
		parsed, ok := parseUint(value)
		if ok {
			values = append(values, parsed)
		}
	}
	return values
}

func parseUint(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if idx := strings.IndexAny(value, " \t("); idx >= 0 {
		value = value[:idx]
	}
	var (
		parsed uint64
		err    error
	)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		parsed, err = strconv.ParseUint(value[2:], 16, 64)
	} else {
		parsed, err = strconv.ParseUint(value, 10, 64)
	}
	return parsed, err == nil
}

func parseInt(value string) int {
	parsed, ok := parseUint(value)
	if !ok {
		return 0
	}
	return int(parsed)
}

func parseEpoch(value string) time.Time {
	value = firstValue(value)
	if value == "" {
		return time.Time{}
	}
	epoch, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return time.Time{}
	}
	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}
