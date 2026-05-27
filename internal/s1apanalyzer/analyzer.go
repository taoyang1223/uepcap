package s1apanalyzer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/analysislimit"
	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

var tsharkS1APFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ip.dst",
	"ipv6.src",
	"ipv6.dst",
	"s1ap.procedureCode",
	"s1ap.S1AP_PDU",
	"s1ap.MME_UE_S1AP_ID",
	"s1ap.ENB_UE_S1AP_ID",
	"nas_eps.nas_msg_emm_type",
	"nas_eps.nas_msg_esm_type",
	"s1ap.gTP_TEID",
	"s1ap.uL_GTP_TEID",
	"s1ap.dL_GTP_TEID",
	"s1ap.e_RAB_ID",
}

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) AnalyzeFile(ctx context.Context, pcapFile string) (*AnalysisResult, error) {
	messages, truncated, err := readMessages(ctx, pcapFile)
	if err != nil {
		return nil, err
	}
	result := analyze(pcapFile, messages)
	result.Truncated = truncated
	if truncated {
		result.MessageLimit = analysislimit.MaxRows("UEPCAP_S1AP_ANALYSIS_MAX_MESSAGES")
	}
	return result, nil
}

var errS1APMessageLimitReached = errors.New("S1AP message limit reached")

func readMessages(ctx context.Context, pcapFile string) ([]*Message, bool, error) {
	limit := analysislimit.MaxRows("UEPCAP_S1AP_ANALYSIS_MAX_MESSAGES")
	messages := make([]*Message, 0, 4096)
	truncated := false
	result, err := tshark.TsharkFieldsStream(ctx, pcapFile, "s1ap", tsharkS1APFields, func(line string) error {
		rowMessages := parseFieldRow(line)
		if limit > 0 && len(messages)+len(rowMessages) > limit {
			remaining := limit - len(messages)
			if remaining > 0 {
				messages = append(messages, rowMessages[:remaining]...)
			}
			truncated = true
			return errS1APMessageLimitReached
		}
		messages = append(messages, rowMessages...)
		return nil
	})
	if errors.Is(err, errS1APMessageLimitReached) {
		return messages, truncated, nil
	}
	if err != nil {
		return nil, false, err
	}
	if result.ExitCode != 0 {
		return nil, false, fmt.Errorf("tshark S1AP analysis failed: %s", strings.TrimSpace(result.Stderr))
	}
	return messages, truncated, nil
}

func analyze(filename string, messages []*Message) *AnalysisResult {
	sort.SliceStable(messages, func(i, j int) bool {
		return messages[i].FrameNumber < messages[j].FrameNumber
	})
	for i, msg := range messages {
		msg.ID = fmt.Sprintf("s1ap-%d", i+1)
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
		messages = append(messages, parseFieldRow(line)...)
	}
	return messages
}

func parseFieldRow(line string) []*Message {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	cols := strings.Split(line, "\t")
	for len(cols) < len(tsharkS1APFields) {
		cols = append(cols, "")
	}

	procedureCodes := splitValues(cols[6])
	pduCodes := splitValues(cols[7])
	sourceIP := firstNonEmpty(cols[2], cols[4])
	destinationIP := firstNonEmpty(cols[3], cols[5])
	if len(procedureCodes) == 0 || net.ParseIP(sourceIP) == nil || net.ParseIP(destinationIP) == nil {
		return nil
	}

	mmeIDs := splitValues(cols[8])
	enbIDs := splitValues(cols[9])
	emmTypes := splitValues(cols[10])
	esmTypes := splitValues(cols[11])
	gtpTEIDs := append(append(splitValues(cols[12]), splitValues(cols[13])...), splitValues(cols[14])...)
	erabIDs := splitValues(cols[15])
	messageCount := max(len(procedureCodes), len(pduCodes))
	messages := make([]*Message, 0, messageCount)
	for i := 0; i < messageCount; i++ {
		procedureCode := indexedValue(procedureCodes, i)
		if procedureCode == "" {
			continue
		}
		pduCode := indexedValue(pduCodes, i)
		pduType := PDUTypeFromCode(pduCode)
		msg := &Message{
			FrameNumber:        parseInt(cols[0]),
			Timestamp:          parseEpoch(cols[1]),
			SourceIP:           sourceIP,
			DestinationIP:      destinationIP,
			Direction:          inferDirection(procedureCode, pduType),
			ProcedureCode:      procedureCode,
			ProcedureName:      ProcedureName(procedureCode),
			PDUCode:            pduCode,
			PDUType:            pduType,
			MMEUES1APID:        indexedValue(mmeIDs, i),
			ENBUES1APID:        indexedValue(enbIDs, i),
			HasNAS:             strictIndexedValue(emmTypes, i) != "" || strictIndexedValue(esmTypes, i) != "",
			GTPTEID:            indexedValue(gtpTEIDs, i),
			ERABID:             indexedValue(erabIDs, i),
			TransactionCapable: isTransactionProcedure(procedureCode),
		}
		msg.WiresharkFilter = messageFilter(msg)
		messages = append(messages, msg)
	}
	return messages
}

func inferDirection(procedureCode string, pduType PDUType) Direction {
	direction := initiatingDirection(procedureCode)
	if pduType == PDUSuccessfulOutcome || pduType == PDUUnsuccessful {
		return oppositeDirection(direction)
	}
	return direction
}

func initiatingDirection(procedureCode string) Direction {
	switch firstToken(procedureCode) {
	case "2", "4", "8", "12", "13", "17", "18", "20", "22", "24", "29", "33", "37", "40", "42", "45", "47", "49", "50", "51", "53":
		return DirectionENBToMME
	case "5", "6", "7", "9", "10", "11", "16", "19", "21", "23", "25", "26", "27", "30", "31", "34", "35", "36", "38", "41", "43", "44", "46", "48", "52":
		return DirectionMMEToENB
	default:
		return DirectionUnknown
	}
}

func oppositeDirection(direction Direction) Direction {
	switch direction {
	case DirectionENBToMME:
		return DirectionMMEToENB
	case DirectionMMEToENB:
		return DirectionENBToMME
	default:
		return DirectionUnknown
	}
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
		tx.ID = fmt.Sprintf("s1ap-tx-%d", i+1)
		tx.StepCount = len(tx.Steps)
	}
	return transactions
}

func isTransactionProcedure(code string) bool {
	switch firstToken(code) {
	case "0", "1", "3", "4", "5", "6", "7", "9", "14", "17", "21", "23", "29", "30", "36", "43", "48", "50", "53":
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
		MMEUES1APID:     msg.MMEUES1APID,
		ENBUES1APID:     msg.ENBUES1APID,
		ERABID:          msg.ERABID,
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
	if tx.MMEUES1APID == "" {
		tx.MMEUES1APID = msg.MMEUES1APID
	}
	if tx.ENBUES1APID == "" {
		tx.ENBUES1APID = msg.ENBUES1APID
	}
	if tx.ERABID == "" {
		tx.ERABID = msg.ERABID
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
		case DirectionENBToMME:
			stats.ENBToMME++
		case DirectionMMEToENB:
			stats.MMEToENB++
		default:
			stats.UnknownDirection++
		}
		if msg.HasNAS || isNASTransportProcedure(msg.ProcedureCode) {
			stats.NASTransport++
		}
		if isERABProcedure(msg.ProcedureCode) {
			stats.ERAB++
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
				Filter:             fmt.Sprintf("s1ap.procedureCode == %s", msg.ProcedureCode),
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
	id := firstNonEmpty(msg.MMEUES1APID, msg.ENBUES1APID)
	return msg.ProcedureCode + ":" + endpointPair(msg.SourceIP, msg.DestinationIP) + ":" + id
}

func endpointPair(left, right string) string {
	if left > right {
		left, right = right, left
	}
	return left + "<->" + right
}

func isNASTransportProcedure(code string) bool {
	switch firstToken(code) {
	case "11", "12", "13", "16", "52":
		return true
	default:
		return false
	}
}

func isERABProcedure(code string) bool {
	switch firstToken(code) {
	case "5", "6", "7", "8", "9", "50":
		return true
	default:
		return false
	}
}

func isUEContextProcedure(code string) bool {
	switch firstToken(code) {
	case "9", "18", "21", "23", "53":
		return true
	default:
		return false
	}
}

func messageFilter(msg *Message) string {
	parts := []string{
		fmt.Sprintf("frame.number == %d", msg.FrameNumber),
		fmt.Sprintf("s1ap.procedureCode == %s", msg.ProcedureCode),
		addressFilter(msg.SourceIP),
		addressFilter(msg.DestinationIP),
	}
	if msg.MMEUES1APID != "" {
		parts = append(parts, fmt.Sprintf("s1ap.MME_UE_S1AP_ID == %s", msg.MMEUES1APID))
	}
	if msg.ENBUES1APID != "" {
		parts = append(parts, fmt.Sprintf("s1ap.ENB_UE_S1AP_ID == %s", msg.ENBUES1APID))
	}
	if msg.ERABID != "" {
		parts = append(parts, fmt.Sprintf("s1ap.e_RAB_ID == %s", msg.ERABID))
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

func indexedValue(values []string, index int) string {
	if index >= 0 && index < len(values) && values[index] != "" {
		return values[index]
	}
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func strictIndexedValue(values []string, index int) string {
	if index >= 0 && index < len(values) {
		return values[index]
	}
	return ""
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
