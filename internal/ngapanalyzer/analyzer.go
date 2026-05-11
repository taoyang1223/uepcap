package ngapanalyzer

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

var tsharkNGAPFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ip.dst",
	"ipv6.src",
	"ipv6.dst",
	"ngap.procedureCode",
	"ngap.NGAP_PDU",
	"ngap.AMF_UE_NGAP_ID",
	"ngap.RAN_UE_NGAP_ID",
	"nas_5gs.mm.message_type",
	"nas_5gs.sm.message_type",
	"ngap.gTP_TEID",
}

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) AnalyzeFile(ctx context.Context, pcapFile string) (*AnalysisResult, error) {
	result, err := tshark.TsharkFields(ctx, pcapFile, "ngap", tsharkNGAPFields)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("tshark NGAP analysis failed: %s", strings.TrimSpace(result.Stderr))
	}
	messages := parseFieldRows(result.Stdout)
	return analyze(pcapFile, messages), nil
}

func analyze(filename string, messages []*Message) *AnalysisResult {
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].FrameNumber < messages[j].FrameNumber
	})
	for i, msg := range messages {
		msg.ID = fmt.Sprintf("ngap-%d", i+1)
	}

	transactions := analyzeTransactions(messages)
	result := &AnalysisResult{
		Filename:       filename,
		AnalyzedAt:     time.Now(),
		TotalPackets:   len(messages),
		Messages:       messages,
		ProcedureStats: calculateProcedureStats(messages),
		Transactions:   transactions,
	}
	result.Statistics = calculateStatistics(messages, transactions)
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
		for len(cols) < len(tsharkNGAPFields) {
			cols = append(cols, "")
		}

		procedureCode := firstValue(cols[6])
		pduCode := firstValue(cols[7])
		sourceIP := firstNonEmpty(cols[2], cols[4])
		destinationIP := firstNonEmpty(cols[3], cols[5])
		if procedureCode == "" || net.ParseIP(sourceIP) == nil || net.ParseIP(destinationIP) == nil {
			continue
		}

		msg := &Message{
			FrameNumber:        parseInt(cols[0]),
			Timestamp:          parseEpoch(cols[1]),
			SourceIP:           sourceIP,
			DestinationIP:      destinationIP,
			Direction:          inferDirection(procedureCode),
			ProcedureCode:      procedureCode,
			ProcedureName:      ProcedureName(procedureCode),
			PDUCode:            pduCode,
			PDUType:            PDUTypeFromCode(pduCode),
			AMFUENGAPID:        firstValue(cols[8]),
			RANUENGAPID:        firstValue(cols[9]),
			HasNAS:             firstValue(cols[10]) != "" || firstValue(cols[11]) != "",
			GTPTEID:            firstValue(cols[12]),
			TransactionCapable: isTransactionProcedure(procedureCode),
		}
		msg.WiresharkFilter = messageFilter(msg)
		messages = append(messages, msg)
	}
	return messages
}

func inferDirection(procedureCode string) Direction {
	switch firstToken(procedureCode) {
	case "15", "46", "21", "42":
		return DirectionGNBToAMF
	case "4", "14", "29", "28", "40", "41", "36":
		return DirectionAMFToGNB
	}
	return DirectionUnknown
}

func analyzeTransactions(messages []*Message) []*Transaction {
	open := make(map[string][]*Transaction)
	transactions := make([]*Transaction, 0)

	for _, msg := range messages {
		if !isTransactionProcedure(msg.ProcedureCode) {
			continue
		}

		key := transactionKey(msg)
		switch msg.PDUType {
		case PDUInitiating:
			tx := newTransaction(msg)
			open[key] = append(open[key], tx)
		case PDUSuccessfulOutcome, PDUUnsuccessful:
			candidates := open[key]
			if len(candidates) == 0 {
				continue
			}
			tx := candidates[0]
			open[key] = candidates[1:]
			addTransactionStep(tx, msg)
			if msg.PDUType == PDUSuccessfulOutcome {
				closeTransaction(tx, TransactionSuccess, msg)
			} else {
				closeTransaction(tx, TransactionFailed, msg)
			}
			transactions = append(transactions, tx)
		}
	}

	for _, list := range open {
		for _, tx := range list {
			closeTransaction(tx, TransactionInProgress, nil)
			transactions = append(transactions, tx)
		}
	}

	sort.SliceStable(transactions, func(i, j int) bool {
		return transactions[i].StartFrame < transactions[j].StartFrame
	})
	for i, tx := range transactions {
		tx.ID = fmt.Sprintf("ngap-tx-%d", i+1)
		tx.StepCount = len(tx.Steps)
	}
	return transactions
}

func isTransactionProcedure(code string) bool {
	switch firstToken(code) {
	case "0", "14", "21", "26", "28", "29", "40", "41":
		return true
	default:
		return false
	}
}

func newTransaction(msg *Message) *Transaction {
	tx := &Transaction{
		ProcedureCode:   msg.ProcedureCode,
		ProcedureName:   msg.ProcedureName,
		Status:          TransactionInProgress,
		StartFrame:      msg.FrameNumber,
		StartTime:       msg.Timestamp,
		RequestMessage:  msg.ProcedureName,
		AMFUENGAPID:     msg.AMFUENGAPID,
		RANUENGAPID:     msg.RANUENGAPID,
		WiresharkFilter: fmt.Sprintf("frame.number == %d", msg.FrameNumber),
	}
	addTransactionStep(tx, msg)
	return tx
}

func addTransactionStep(tx *Transaction, msg *Message) {
	if tx == nil || msg == nil {
		return
	}
	tx.Steps = append(tx.Steps, TransactionStep{
		FrameNumber:   msg.FrameNumber,
		Timestamp:     msg.Timestamp,
		Direction:     msg.Direction,
		ProcedureName: msg.ProcedureName,
		PDUType:       msg.PDUType,
	})
	tx.EndFrame = msg.FrameNumber
	tx.EndTime = msg.Timestamp
	tx.ResultMessage = pduTypeLabel(msg.PDUType)
	if tx.AMFUENGAPID == "" {
		tx.AMFUENGAPID = msg.AMFUENGAPID
	}
	if tx.RANUENGAPID == "" {
		tx.RANUENGAPID = msg.RANUENGAPID
	}
	if !tx.StartTime.IsZero() && !tx.EndTime.IsZero() {
		tx.DurationMs = tx.EndTime.Sub(tx.StartTime).Seconds() * 1000
	}
	tx.WiresharkFilter = fmt.Sprintf("frame.number >= %d && frame.number <= %d", tx.StartFrame, tx.EndFrame)
}

func closeTransaction(tx *Transaction, status TransactionStatus, msg *Message) {
	if tx == nil {
		return
	}
	tx.Status = status
	if msg != nil {
		tx.EndFrame = msg.FrameNumber
		tx.EndTime = msg.Timestamp
		tx.ResultMessage = pduTypeLabel(msg.PDUType)
	}
	if !tx.StartTime.IsZero() && !tx.EndTime.IsZero() {
		tx.DurationMs = tx.EndTime.Sub(tx.StartTime).Seconds() * 1000
	}
	if tx.EndFrame > 0 {
		tx.WiresharkFilter = fmt.Sprintf("frame.number >= %d && frame.number <= %d", tx.StartFrame, tx.EndFrame)
	}
}

func calculateStatistics(messages []*Message, transactions []*Transaction) Statistics {
	stats := Statistics{TotalMessages: len(messages)}
	for _, msg := range messages {
		switch msg.PDUType {
		case PDUInitiating:
			stats.Initiating++
		case PDUSuccessfulOutcome:
			stats.SuccessfulOutcome++
		case PDUUnsuccessful:
			stats.UnsuccessfulOutcome++
		}
		switch msg.Direction {
		case DirectionGNBToAMF:
			stats.GNBToAMF++
		case DirectionAMFToGNB:
			stats.AMFToGNB++
		default:
			stats.UnknownDirection++
		}
		if msg.HasNAS || isNASTransportProcedure(msg.ProcedureCode) {
			stats.NASTransport++
		}
		if isPDUSessionResourceProcedure(msg.ProcedureCode) {
			stats.PDUSessionResource++
		}
		if isUEContextProcedure(msg.ProcedureCode) {
			stats.UEContext++
		}
		if msg.TransactionCapable {
			stats.TransactionCapableMessages++
		} else {
			stats.MessageOnlyMessages++
		}
	}
	stats.TotalTransactions = len(transactions)
	for _, tx := range transactions {
		switch tx.Status {
		case TransactionSuccess:
			stats.SuccessfulTransactions++
		case TransactionFailed:
			stats.FailedTransactions++
		default:
			stats.InProgressTransactions++
		}
	}
	if stats.TotalTransactions > 0 {
		stats.TransactionSuccessRate = float64(stats.SuccessfulTransactions) / float64(stats.TotalTransactions) * 100
	}
	return stats
}

func calculateProcedureStats(messages []*Message) []ProcedureCount {
	byCode := make(map[string]*ProcedureCount)
	for _, msg := range messages {
		if _, ok := byCode[msg.ProcedureCode]; !ok {
			byCode[msg.ProcedureCode] = &ProcedureCount{
				Code:               msg.ProcedureCode,
				Name:               msg.ProcedureName,
				Filter:             fmt.Sprintf("ngap.procedureCode == %s", msg.ProcedureCode),
				TransactionCapable: isTransactionProcedure(msg.ProcedureCode),
			}
		}
		byCode[msg.ProcedureCode].Count++
	}
	stats := make([]ProcedureCount, 0, len(byCode))
	for _, item := range byCode {
		stats = append(stats, *item)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Count != stats[j].Count {
			return stats[i].Count > stats[j].Count
		}
		return stats[i].Name < stats[j].Name
	})
	return stats
}

func transactionKey(msg *Message) string {
	id := firstNonEmpty(msg.AMFUENGAPID, msg.RANUENGAPID)
	return msg.ProcedureCode + ":" + id
}

func isNASTransportProcedure(code string) bool {
	switch firstToken(code) {
	case "4", "15", "19", "36", "46":
		return true
	default:
		return false
	}
}

func isPDUSessionResourceProcedure(code string) bool {
	switch firstToken(code) {
	case "26", "28", "29", "30":
		return true
	default:
		return false
	}
}

func isUEContextProcedure(code string) bool {
	switch firstToken(code) {
	case "14", "40", "41", "42":
		return true
	default:
		return false
	}
}

func messageFilter(msg *Message) string {
	parts := []string{
		fmt.Sprintf("frame.number == %d", msg.FrameNumber),
		fmt.Sprintf("ngap.procedureCode == %s", msg.ProcedureCode),
		addressFilter(msg.SourceIP),
		addressFilter(msg.DestinationIP),
	}
	if msg.AMFUENGAPID != "" {
		parts = append(parts, fmt.Sprintf("ngap.AMF_UE_NGAP_ID == %s", msg.AMFUENGAPID))
	}
	if msg.RANUENGAPID != "" {
		parts = append(parts, fmt.Sprintf("ngap.RAN_UE_NGAP_ID == %s", msg.RANUENGAPID))
	}
	return strings.Join(parts, " && ")
}

func addressFilter(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("ipv6.addr == %s", ip)
	}
	return fmt.Sprintf("ip.addr == %s", ip)
}

func pduTypeLabel(pdu PDUType) string {
	switch pdu {
	case PDUInitiating:
		return "Initiating"
	case PDUSuccessfulOutcome:
		return "Successful Outcome"
	case PDUUnsuccessful:
		return "Unsuccessful Outcome"
	default:
		return "Unknown"
	}
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
	parsed, _ := strconv.Atoi(value)
	return parsed
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
