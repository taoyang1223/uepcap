package nasanalyzer

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

var tsharkNASFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ip.dst",
	"ipv6.src",
	"ipv6.dst",
	"ngap.procedureCode",
	"ngap.NGAP_PDU",
	"nas_5gs.mm.message_type",
	"nas_5gs.sm.message_type",
	"nas_5gs.security_header_type",
	"nas_5gs.seq_no",
	"nas_5gs.mm.elem_id",
}

type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) AnalyzeFile(ctx context.Context, pcapFile string) (*AnalysisResult, error) {
	result, err := tshark.TsharkFields(ctx, pcapFile, "nas-5gs", tsharkNASFields)
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("tshark NAS analysis failed: %s", strings.TrimSpace(result.Stderr))
	}

	messages := parseFieldRows(result.Stdout)
	return analyze(pcapFile, messages), nil
}

func analyze(filename string, messages []*Message) *AnalysisResult {
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].FrameNumber < messages[j].FrameNumber
	})
	for i, msg := range messages {
		msg.ID = fmt.Sprintf("nas-%d", i+1)
	}

	result := &AnalysisResult{
		Filename:     filename,
		AnalyzedAt:   time.Now(),
		TotalPackets: len(messages),
		Messages:     messages,
	}
	result.TypeStats = calculateTypeStats(messages)
	result.Flows = analyzeFlows(messages)
	result.Statistics = calculateStatistics(messages, result.Flows)
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
		for len(cols) < len(tsharkNASFields) {
			cols = append(cols, "")
		}

		mmType := normalizeHex(firstValue(cols[8]))
		smType := normalizeHex(firstValue(cols[9]))
		if mmType == "" && smType == "" {
			continue
		}

		category := CategoryMM
		messageCode := mmType
		messageName := MMMessageTypeName(mmType)
		if smType != "" {
			category = CategorySM
			messageCode = smType
			messageName = SMMessageTypeName(smType)
		}

		sourceIP := firstNonEmpty(cols[2], cols[4])
		destinationIP := firstNonEmpty(cols[3], cols[5])
		if net.ParseIP(sourceIP) == nil || net.ParseIP(destinationIP) == nil {
			continue
		}

		securityHeader := firstValue(cols[10])
		msg := &Message{
			FrameNumber:        parseInt(cols[0]),
			Timestamp:          parseEpoch(cols[1]),
			SourceIP:           sourceIP,
			DestinationIP:      destinationIP,
			Direction:          directionFromNGAP(firstValue(cols[6]), mmType),
			Category:           category,
			MessageTypeCode:    messageCode,
			MessageType:        messageName,
			SecurityHeaderType: securityHeader,
			SecurityHeaderName: SecurityHeaderName(securityHeader),
			SequenceNumber:     firstValue(cols[11]),
			NGAPProcedureCode:  firstValue(cols[6]),
			NGAPPDU:            firstValue(cols[7]),
			ElementIDs:         splitValues(cols[12]),
		}
		msg.WiresharkFilter = messageFilter(msg)
		messages = append(messages, msg)
	}

	return messages
}

func directionFromNGAP(procedureCode, mmType string) NASDirection {
	switch firstToken(procedureCode) {
	case "46":
		return DirectionUplink
	case "4":
		return DirectionDownlink
	}
	switch normalizeHex(mmType) {
	case "0x67":
		return DirectionUplink
	case "0x68":
		return DirectionDownlink
	default:
		return DirectionUnknown
	}
}

func calculateStatistics(messages []*Message, flows []*Flow) Statistics {
	stats := Statistics{TotalMessages: len(messages)}
	for _, msg := range messages {
		switch msg.Category {
		case CategoryMM:
			stats.MMMessages++
		case CategorySM:
			stats.SMMessages++
		}
		switch msg.Direction {
		case DirectionUplink:
			stats.Uplink++
		case DirectionDownlink:
			stats.Downlink++
		default:
			stats.Unknown++
		}
		if firstToken(msg.SecurityHeaderType) == "" || firstToken(msg.SecurityHeaderType) == "0" || firstToken(msg.SecurityHeaderType) == "0x0" {
			stats.Plain++
		} else {
			stats.Protected++
		}
	}
	stats.TotalFlows = len(flows)
	for _, flow := range flows {
		switch flow.Status {
		case FlowStatusSuccess:
			stats.SuccessfulFlows++
		case FlowStatusFailed:
			stats.FailedFlows++
		default:
			stats.InProgressFlows++
		}
		switch flow.FlowType {
		case FlowRegistration:
			stats.RegistrationFlows++
		case FlowAuthentication:
			stats.Authentication++
		case FlowSecurityMode:
			stats.SecurityMode++
		case FlowPDUSessionEst:
			stats.PDUSession++
		}
	}
	if stats.TotalFlows > 0 {
		stats.FlowSuccessRate = float64(stats.SuccessfulFlows) / float64(stats.TotalFlows) * 100
	}
	return stats
}

func analyzeFlows(messages []*Message) []*Flow {
	flows := make([]*Flow, 0)
	var registration *Flow
	var authentication *Flow
	var securityMode *Flow
	var pduSession *Flow

	for _, msg := range messages {
		code := normalizeHex(msg.MessageTypeCode)

		if registration != nil && msg.Category == CategoryMM {
			addFlowStep(registration, msg)
			switch code {
			case "0x44":
				closeFlow(registration, FlowStatusFailed, msg, "Registration rejected")
				flows = append(flows, registration)
				registration = nil
			case "0x43":
				closeFlow(registration, FlowStatusSuccess, msg, "")
				flows = append(flows, registration)
				registration = nil
			}
		}

		if authentication != nil && msg.Category == CategoryMM {
			switch code {
			case "0x57", "0x59", "0x58", "0x5a":
				addFlowStep(authentication, msg)
				switch code {
				case "0x57", "0x5a":
					closeFlow(authentication, FlowStatusSuccess, msg, "")
				case "0x59":
					closeFlow(authentication, FlowStatusFailed, msg, "Authentication failure")
				case "0x58":
					closeFlow(authentication, FlowStatusFailed, msg, "Authentication rejected")
				}
				flows = append(flows, authentication)
				authentication = nil
			}
		}

		if securityMode != nil && msg.Category == CategoryMM {
			switch code {
			case "0x5e", "0x5f":
				addFlowStep(securityMode, msg)
				if code == "0x5e" {
					closeFlow(securityMode, FlowStatusSuccess, msg, "")
				} else {
					closeFlow(securityMode, FlowStatusFailed, msg, "Security mode rejected")
				}
				flows = append(flows, securityMode)
				securityMode = nil
			}
		}

		if pduSession != nil && msg.Category == CategorySM {
			switch code {
			case "0xc2", "0xc3":
				addFlowStep(pduSession, msg)
				if code == "0xc2" {
					closeFlow(pduSession, FlowStatusSuccess, msg, "")
				} else {
					closeFlow(pduSession, FlowStatusFailed, msg, "PDU session establishment rejected")
				}
				flows = append(flows, pduSession)
				pduSession = nil
			}
		}

		switch code {
		case "0x41":
			if registration != nil {
				closeFlow(registration, FlowStatusInProgress, registrationMessage(registration), "")
				flows = append(flows, registration)
			}
			registration = newFlow(FlowRegistration, msg)
		case "0x56":
			if authentication != nil {
				closeFlow(authentication, FlowStatusInProgress, registrationMessage(authentication), "")
				flows = append(flows, authentication)
			}
			authentication = newFlow(FlowAuthentication, msg)
		case "0x5d":
			if securityMode != nil {
				closeFlow(securityMode, FlowStatusInProgress, registrationMessage(securityMode), "")
				flows = append(flows, securityMode)
			}
			securityMode = newFlow(FlowSecurityMode, msg)
		case "0xc1":
			if pduSession != nil {
				closeFlow(pduSession, FlowStatusInProgress, registrationMessage(pduSession), "")
				flows = append(flows, pduSession)
			}
			pduSession = newFlow(FlowPDUSessionEst, msg)
		}
	}

	for _, flow := range []*Flow{registration, authentication, securityMode, pduSession} {
		if flow != nil {
			closeFlow(flow, FlowStatusInProgress, registrationMessage(flow), "")
			flows = append(flows, flow)
		}
	}

	sort.SliceStable(flows, func(i, j int) bool {
		return flows[i].StartFrame < flows[j].StartFrame
	})
	for i, flow := range flows {
		flow.ID = fmt.Sprintf("nas-flow-%d", i+1)
		flow.StepCount = len(flow.Steps)
	}
	return flows
}

func newFlow(flowType FlowType, msg *Message) *Flow {
	flow := &Flow{
		FlowType:        flowType,
		Status:          FlowStatusInProgress,
		StartFrame:      msg.FrameNumber,
		StartTime:       msg.Timestamp,
		RequestMessage:  msg.MessageType,
		WiresharkFilter: fmt.Sprintf("frame.number == %d", msg.FrameNumber),
	}
	addFlowStep(flow, msg)
	return flow
}

func addFlowStep(flow *Flow, msg *Message) {
	if flow == nil || msg == nil {
		return
	}
	if len(flow.Steps) > 0 && flow.Steps[len(flow.Steps)-1].FrameNumber == msg.FrameNumber {
		return
	}
	flow.Steps = append(flow.Steps, FlowStep{
		FrameNumber: msg.FrameNumber,
		Timestamp:   msg.Timestamp,
		Direction:   msg.Direction,
		Category:    msg.Category,
		MessageType: msg.MessageType,
		Code:        msg.MessageTypeCode,
	})
	flow.EndFrame = msg.FrameNumber
	flow.EndTime = msg.Timestamp
	if !flow.StartTime.IsZero() && !flow.EndTime.IsZero() {
		flow.DurationMs = flow.EndTime.Sub(flow.StartTime).Seconds() * 1000
	}
	flow.ResultMessage = msg.MessageType
	flow.WiresharkFilter = fmt.Sprintf("frame.number >= %d && frame.number <= %d", flow.StartFrame, flow.EndFrame)
}

func closeFlow(flow *Flow, status FlowStatus, msg *Message, failureReason string) {
	if flow == nil {
		return
	}
	flow.Status = status
	if msg != nil {
		flow.EndFrame = msg.FrameNumber
		flow.EndTime = msg.Timestamp
		if !flow.StartTime.IsZero() && !flow.EndTime.IsZero() {
			flow.DurationMs = flow.EndTime.Sub(flow.StartTime).Seconds() * 1000
		}
		flow.ResultMessage = msg.MessageType
	}
	flow.FailureReason = failureReason
	if flow.EndFrame > 0 {
		flow.WiresharkFilter = fmt.Sprintf("frame.number >= %d && frame.number <= %d", flow.StartFrame, flow.EndFrame)
	}
}

func registrationMessage(flow *Flow) *Message {
	if flow == nil || len(flow.Steps) == 0 {
		return nil
	}
	step := flow.Steps[len(flow.Steps)-1]
	return &Message{FrameNumber: step.FrameNumber, Timestamp: step.Timestamp, MessageType: step.MessageType}
}

func calculateTypeStats(messages []*Message) []TypeCount {
	byKey := make(map[string]*TypeCount)
	for _, msg := range messages {
		key := string(msg.Category) + ":" + msg.MessageTypeCode
		if _, ok := byKey[key]; !ok {
			field := "nas_5gs.mm.message_type"
			if msg.Category == CategorySM {
				field = "nas_5gs.sm.message_type"
			}
			byKey[key] = &TypeCount{
				Category: msg.Category,
				Code:     msg.MessageTypeCode,
				Name:     msg.MessageType,
				Filter:   fmt.Sprintf("%s == %s", field, displayHex(msg.MessageTypeCode)),
			}
		}
		byKey[key].Count++
	}

	stats := make([]TypeCount, 0, len(byKey))
	for _, item := range byKey {
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

func messageFilter(msg *Message) string {
	field := "nas_5gs.mm.message_type"
	if msg.Category == CategorySM {
		field = "nas_5gs.sm.message_type"
	}
	parts := []string{
		fmt.Sprintf("frame.number == %d", msg.FrameNumber),
		fmt.Sprintf("%s == %s", field, displayHex(msg.MessageTypeCode)),
		addressFilter(msg.SourceIP),
		addressFilter(msg.DestinationIP),
	}
	return strings.Join(parts, " && ")
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

func normalizeHex(value string) string {
	value = strings.ToLower(firstToken(value))
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "0x") {
		parsed, err := strconv.ParseInt(strings.TrimPrefix(value, "0x"), 16, 64)
		if err == nil {
			return fmt.Sprintf("0x%x", parsed)
		}
		return value
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		return fmt.Sprintf("0x%x", parsed)
	}
	return value
}

func displayHex(value string) string {
	normalized := normalizeHex(value)
	if normalized == "" {
		return value
	}
	return "0x" + strings.ToUpper(strings.TrimPrefix(normalized, "0x"))
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
