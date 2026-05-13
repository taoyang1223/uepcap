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

const (
	DefaultTimeout = 3 * time.Second

	pfcpTransactionDisplayFilter = "(pfcp.msg_type == 1 || pfcp.msg_type == 2 || pfcp.msg_type == 5 || pfcp.msg_type == 6 || pfcp.msg_type == 7 || pfcp.msg_type == 8 || pfcp.msg_type == 9 || pfcp.msg_type == 10 || pfcp.msg_type == 12 || pfcp.msg_type == 13 || (pfcp.msg_type >= 50 && pfcp.msg_type <= 57))"
)

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
	result, err := tshark.TsharkFields(ctx, pcapFile, pfcpTransactionDisplayFilter, tsharkSessionFields)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("tshark PFCP transaction analysis failed: %s", strings.TrimSpace(result.Stderr))
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

	requests := make(map[string][]*Message)
	responses := make(map[string]*Message)
	requestCounts := make(map[string][]int)

	for _, msg := range messages {
		if !isSessionMessage(msg.MessageTypeCode) {
			continue
		}

		key := makeKey(msg)
		if isRequest(msg.MessageTypeCode) {
			retransmitKey := makeRetransmitKey(msg)
			requestCounts[retransmitKey] = append(requestCounts[retransmitKey], msg.FrameNumber)
			requests[key] = append(requests[key], msg)
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
	for key, reqs := range requests {
		if len(reqs) == 0 {
			continue
		}
		if resp, ok := responses[key]; ok {
			req := reqs[0]
			txID++
			tx := newTransaction(txID, req)
			if frames := requestCounts[makeRetransmitKey(req)]; len(frames) > 1 {
				tx.RetransmitCount = len(frames) - 1
				tx.RetransmitFrames = append([]int(nil), frames[1:]...)
			}
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
			transactions = append(transactions, tx)
			continue
		}

		seenRetries := make(map[string]int)
		for _, req := range reqs {
			txID++
			tx := newTransaction(txID, req)
			tx.Status = StatusNoResponse
			retransmitKey := makeRetransmitKey(req)
			if seenRetries[retransmitKey] > 0 {
				tx.RetransmitCount = 1
			}
			seenRetries[retransmitKey]++
			transactions = append(transactions, tx)
		}
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

func newTransaction(id int, req *Message) *Transaction {
	return &Transaction{
		ID:              fmt.Sprintf("tx-%d", id),
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

func makeRetransmitKey(msg *Message) string {
	return fmt.Sprintf(
		"%s:%s:%d:%d:%d:%d:%s:%s",
		msg.SourceIP,
		msg.DestinationIP,
		msg.MessageTypeCode,
		msg.SequenceNumber,
		msg.HeaderSEID,
		msg.FSEID,
		msg.FSEIDIPv4,
		msg.FSEIDIPv6,
	)
}

func transactionFilter(msg *Message) string {
	parts := []string{
		transactionMessageTypeFilter(msg.MessageTypeCode),
		fmt.Sprintf("pfcp.seqno == %d", msg.SequenceNumber),
		addressFilter(msg.SourceIP),
		addressFilter(msg.DestinationIP),
	}
	if msg.HeaderSEID != 0 {
		parts = append(parts, fmt.Sprintf("pfcp.seid == %d", msg.HeaderSEID))
	}
	return strings.Join(parts, " && ")
}

func transactionMessageTypeFilter(msgType uint8) string {
	switch msgType {
	case 1, 2:
		return "(pfcp.msg_type == 1 || pfcp.msg_type == 2)"
	case 5, 6:
		return "(pfcp.msg_type == 5 || pfcp.msg_type == 6)"
	case 7, 8:
		return "(pfcp.msg_type == 7 || pfcp.msg_type == 8)"
	case 9, 10:
		return "(pfcp.msg_type == 9 || pfcp.msg_type == 10)"
	case 12, 13:
		return "(pfcp.msg_type == 12 || pfcp.msg_type == 13)"
	case 50, 51:
		return "(pfcp.msg_type == 50 || pfcp.msg_type == 51)"
	case 52, 53:
		return "(pfcp.msg_type == 52 || pfcp.msg_type == 53)"
	case 54, 55:
		return "(pfcp.msg_type == 54 || pfcp.msg_type == 55)"
	case 56, 57:
		return "(pfcp.msg_type == 56 || pfcp.msg_type == 57)"
	default:
		return fmt.Sprintf("pfcp.msg_type == %d", msgType)
	}
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

		if tx.RetransmitCount > 0 {
			stats.Retransmit++
		}

		switch tx.MessageType {
		case "Heartbeat":
			stats.Heartbeat++
		case "Association Setup":
			stats.AssociationSetup++
		case "Association Update":
			stats.AssociationUpdate++
		case "Association Release":
			stats.AssociationRelease++
		case "Node Report":
			stats.NodeReport++
		case "Session Establishment":
			stats.SessionEstablishment++
		case "Session Modification":
			stats.SessionModification++
		case "Session Deletion":
			stats.SessionDeletion++
		case "Session Report":
			stats.SessionReport++
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
