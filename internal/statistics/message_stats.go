package statistics

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

const (
	fieldNASMMMessageType = "nas_5gs.mm.message_type"
	fieldNASSMMessageType = "nas_5gs.sm.message_type"
	fieldNASMMElemID      = "nas_5gs.mm.elem_id"
	fieldNGAPProcedure    = "ngap.procedureCode"
	fieldNGAPPDU          = "ngap.NGAP_PDU"
	fieldGTPv2MessageType = "gtpv2.message_type"
	fieldPFCPMessageType  = "pfcp.msg_type"
)

const statsProtocolFilter = "nas-5gs or ngap or gtpv2 or pfcp"

var tsharkFields = []string{
	fieldNASMMMessageType,
	fieldNASSMMessageType,
	fieldNASMMElemID,
	fieldNGAPProcedure,
	fieldNGAPPDU,
	fieldGTPv2MessageType,
	fieldPFCPMessageType,
}

type matchKind string

const (
	matchNASMM matchKind = "nas_mm"
	matchNASSM matchKind = "nas_sm"
	matchNGAP  matchKind = "ngap"
	matchGTPv2 matchKind = "gtpv2"
	matchPFCP  matchKind = "pfcp"
)

// Result is the full message statistics response.
type Result struct {
	ScopeFilter string   `json:"scope_filter,omitempty"`
	Modules     []Module `json:"modules"`
}

// Module groups related signaling message statistics.
type Module struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Standard   string `json:"standard,omitempty"`
	RawTotal   int    `json:"raw_total"`
	FinalTotal int    `json:"final_total"`
	Items      []Item `json:"items"`
}

// Item is one configured message type and its counted result.
type Item struct {
	Key              string `json:"key"`
	Name             string `json:"name"`
	Filter           string `json:"filter"`
	RawCount         int    `json:"raw_count"`
	Correction       int    `json:"correction"`
	Count            int    `json:"count"`
	CorrectionReason string `json:"correction_reason,omitempty"`
}

type messageDefinition struct {
	Key    string
	Name   string
	Kind   matchKind
	Value  string
	PDU    string
	Filter string
}

type moduleDefinition struct {
	Key      string
	Name     string
	Standard string
	Items    []messageDefinition
}

type definitionIndex struct {
	nasMM map[string][]messageDefinition
	nasSM map[string][]messageDefinition
	ngap  map[string][]messageDefinition
	gtpv2 map[string][]messageDefinition
	pfcp  map[string][]messageDefinition
}

var moduleDefinitions = []moduleDefinition{
	{
		Key:      "nas",
		Name:     "NAS消息",
		Standard: "TS 24.501",
		Items: []messageDefinition{
			nasMM("registration-request", "REGISTRATION REQUEST", "0x41"),
			nasMM("registration-accept", "REGISTRATION ACCEPT", "0x42"),
			nasMM("registration-complete", "REGISTRATION COMPLETE", "0x43"),
			nasMM("registration-reject", "REGISTRATION REJECT", "0x44"),
			nasMM("deregistration-request", "DEREGISTRATION REQUEST", "0x45"),
			nasMM("deregistration-accept", "DEREGISTRATION ACCEPT", "0x46"),
			nasMM("service-request", "SERVICE REQUEST", "0x4C"),
			nasMM("service-accept", "SERVICE ACCEPT", "0x4E"),
			nasMM("control-plane-service-request", "CONTROL PLANE SERVICE REQUEST", "0x4F"),
			nasMM("authentication-reject", "AUTHENTICATION REJECT", "0x58"),
			nasMM("authentication-failure", "AUTHENTICATION FAILURE", "0x59"),
			nasMM("security-mode-command", "SECURITY MODE COMMAND", "0x5D"),
			nasMM("security-mode-complete", "SECURITY MODE COMPLETE", "0x5E"),
			nasMM("security-mode-reject", "SECURITY MODE REJECT", "0x5F"),
			nasMM("5gmm-status", "5GMM STATUS", "0x64"),
			nasMM("ul-nas-transport", "UL NAS TRANSPORT", "0x67"),
			nasMM("dl-nas-transport", "DL NAS TRANSPORT", "0x68"),
		},
	},
	{
		Key:      "ngap",
		Name:     "NGAP消息",
		Standard: "TS 38.413",
		Items: []messageDefinition{
			ngap("initial-ue-message", "Initial UE Message", "15", "0"),
			ngap("downlink-nas-transport", "Downlink NAS Transport", "4", "0"),
			ngap("uplink-nas-transport", "Uplink NAS Transport", "46", "0"),
			ngap("nas-non-delivery-indication", "NAS Non Delivery Indication", "19", "0"),
			ngap("reroute-nas-request", "Reroute NAS Request", "36", "0"),
			ngap("initial-context-setup-request", "Initial Context Setup Request", "14", "0"),
			ngap("initial-context-setup-response", "Initial Context Setup Response", "14", "1"),
			ngap("initial-context-setup-failure", "Initial Context Setup Failure", "14", "2"),
			ngap("ue-context-release-request", "UE Context Release Request", "42", "0"),
			ngap("ue-context-release-command", "UE Context Release Command", "41", "0"),
			ngap("ue-context-release-complete", "UE Context Release Complete", "41", "1"),
			ngap("ue-context-modification-request", "UE Context Modification Request", "40", "0"),
			ngap("ue-context-modification-response", "UE Context Modification Response", "40", "1"),
			ngap("ue-context-modification-failure", "UE Context Modification Failure", "40", "2"),
			ngap("pdu-session-resource-setup-request", "PDU Session Resource Setup Request", "29", "0"),
			ngap("pdu-session-resource-setup-response", "PDU Session Resource Setup Response", "29", "1"),
			ngap("pdu-session-resource-release-command", "PDU Session Resource Release Command", "28", "0"),
			ngap("pdu-session-resource-release-response", "PDU Session Resource Release Response", "28", "1"),
			ngap("pdu-session-resource-modify-request", "PDU Session Resource Modify Request", "26", "0"),
			ngap("pdu-session-resource-modify-response", "PDU Session Resource Modify Response", "26", "1"),
			ngap("pdu-session-resource-notify", "PDU Session Resource Notify", "30", "0"),
			ngap("error-indication", "Error Indication", "9", "0"),
		},
	},
	{
		Key:      "s11",
		Name:     "S11消息",
		Standard: "TS 29.274",
		Items: []messageDefinition{
			gtpv2("create-session-request", "Create Session Request", "32"),
			gtpv2("create-session-response", "Create Session Response", "33"),
			gtpv2("modify-bearer-request", "Modify Bearer Request", "34"),
			gtpv2("modify-bearer-response", "Modify Bearer Response", "35"),
			gtpv2("delete-session-request", "Delete Session Request", "36"),
			gtpv2("delete-session-response", "Delete Session Response", "37"),
			gtpv2("change-notification-request", "Change Notification Request", "38"),
			gtpv2("change-notification-response", "Change Notification Response", "39"),
			gtpv2("create-bearer-request", "Create Bearer Request", "95"),
			gtpv2("update-bearer-request", "Update Bearer Request", "97"),
			gtpv2("update-bearer-response", "Update Bearer Response", "98"),
			gtpv2("delete-bearer-request", "Delete Bearer Request", "99"),
			gtpv2("delete-bearer-response", "Delete Bearer Response", "100"),
			gtpv2("delete-pdn-connection-set-request", "Delete PDN Connection Set Request", "101"),
			gtpv2("delete-pdn-connection-set-response", "Delete PDN Connection Set Response", "102"),
			gtpv2("create-forwarding-tunnel-request", "Create Forwarding Tunnel Request", "160"),
			gtpv2("create-forwarding-tunnel-response", "Create Forwarding Tunnel Response", "161"),
			gtpv2("create-indirect-data-forwarding-tunnel-request", "Create Indirect Data Forwarding Tunnel Request", "166"),
			gtpv2("delete-indirect-data-forwarding-tunnel-request", "Delete Indirect Data Forwarding Tunnel Request", "168"),
			gtpv2("pgw-restart-notification", "PGW Restart Notification", "179"),
			gtpv2("pgw-restart-notification-acknowledge", "PGW Restart Notification Acknowledge", "180"),
			gtpv2("stop-paging-indication", "Stop Paging Indication", "73"),
			gtpv2("modify-access-bearers-request", "Modify Access Bearers Request", "211"),
			gtpv2("modify-access-bearers-response", "Modify Access Bearers Response", "212"),
			gtpv2("release-access-bearers-request", "Release Access Bearers Request", "170"),
			gtpv2("release-access-bearers-response", "Release Access Bearers Response", "171"),
			gtpv2("trace-session-activation", "Trace Session Activation", "71"),
			gtpv2("trace-session-deactivation", "Trace Session Deactivation", "72"),
		},
	},
	{
		Key:      "sm-nas",
		Name:     "SM NAS消息",
		Standard: "TS 24.501",
		Items: []messageDefinition{
			nasSM("pdu-session-establishment-request", "PDU SESSION ESTABLISHMENT REQUEST", "0xC1"),
			nasSM("pdu-session-establishment-accept", "PDU SESSION ESTABLISHMENT ACCEPT", "0xC2"),
			nasSM("pdu-session-establishment-reject", "PDU SESSION ESTABLISHMENT REJECT", "0xC3"),
			nasSM("pdu-session-authentication-command", "PDU SESSION AUTHENTICATION COMMAND", "0xC5"),
			nasSM("pdu-session-authentication-complete", "PDU SESSION AUTHENTICATION COMPLETE", "0xC6"),
			nasSM("pdu-session-authentication-result", "PDU SESSION AUTHENTICATION RESULT", "0xC7"),
			nasSM("pdu-session-modification-request", "PDU SESSION MODIFICATION REQUEST", "0xC9"),
			nasSM("pdu-session-modification-reject", "PDU SESSION MODIFICATION REJECT", "0xCA"),
			nasSM("pdu-session-modification-command", "PDU SESSION MODIFICATION COMMAND", "0xCB"),
			nasSM("pdu-session-modification-complete", "PDU SESSION MODIFICATION COMPLETE", "0xCC"),
			nasSM("pdu-session-release-request", "PDU SESSION RELEASE REQUEST", "0xD1"),
			nasSM("pdu-session-release-reject", "PDU SESSION RELEASE REJECT", "0xD2"),
			nasSM("pdu-session-release-command", "PDU SESSION RELEASE COMMAND", "0xD3"),
			nasSM("pdu-session-release-complete", "PDU SESSION RELEASE COMPLETE", "0xD4"),
			nasSM("5gsm-status", "5GSM STATUS", "0xD6"),
		},
	},
	{
		Key:      "pfcp",
		Name:     "PFCP消息",
		Standard: "TS 29.244",
		Items: []messageDefinition{
			pfcp("pfcp-heartbeat-request", "PFCP Heartbeat Request", "1"),
			pfcp("pfcp-heartbeat-response", "PFCP Heartbeat Response", "2"),
			pfcp("pfcp-association-setup-request", "PFCP Association Setup Request", "5"),
			pfcp("pfcp-association-setup-response", "PFCP Association Setup Response", "6"),
			pfcp("pfcp-association-update-request", "PFCP Association Update Request", "7"),
			pfcp("pfcp-association-update-response", "PFCP Association Update Response", "8"),
			pfcp("pfcp-association-release-request", "PFCP Association Release Request", "9"),
			pfcp("pfcp-association-release-response", "PFCP Association Release Response", "10"),
			pfcp("pfcp-node-report-request", "PFCP Node Report Request", "12"),
			pfcp("pfcp-node-report-response", "PFCP Node Report Response", "13"),
			pfcp("pfcp-session-establishment-request", "PFCP Session Establishment Request", "50"),
			pfcp("pfcp-session-establishment-response", "PFCP Session Establishment Response", "51"),
			pfcp("pfcp-session-modification-request", "PFCP Session Modification Request", "52"),
			pfcp("pfcp-session-modification-response", "PFCP Session Modification Response", "53"),
			pfcp("pfcp-session-deletion-request", "PFCP Session Deletion Request", "54"),
			pfcp("pfcp-session-deletion-response", "PFCP Session Deletion Response", "55"),
			pfcp("pfcp-session-report-request", "PFCP Session Report Request", "56"),
			pfcp("pfcp-session-report-response", "PFCP Session Report Response", "57"),
		},
	},
}

func nasMM(key, name, value string) messageDefinition {
	value = normalizeHexDefinition(value)
	return messageDefinition{
		Key:    key,
		Name:   name,
		Kind:   matchNASMM,
		Value:  value,
		Filter: fmt.Sprintf("%s == %s", fieldNASMMMessageType, displayHex(value)),
	}
}

func nasSM(key, name, value string) messageDefinition {
	value = normalizeHexDefinition(value)
	return messageDefinition{
		Key:    key,
		Name:   name,
		Kind:   matchNASSM,
		Value:  value,
		Filter: fmt.Sprintf("%s == %s", fieldNASSMMessageType, displayHex(value)),
	}
}

func ngap(key, name, procedure, pdu string) messageDefinition {
	return messageDefinition{
		Key:    key,
		Name:   name,
		Kind:   matchNGAP,
		Value:  procedure,
		PDU:    pdu,
		Filter: fmt.Sprintf("(%s == %s) && (%s == %s)", fieldNGAPProcedure, procedure, fieldNGAPPDU, pdu),
	}
}

func gtpv2(key, name, value string) messageDefinition {
	return messageDefinition{
		Key:    key,
		Name:   name,
		Kind:   matchGTPv2,
		Value:  value,
		Filter: fmt.Sprintf("%s == %s", fieldGTPv2MessageType, value),
	}
}

func pfcp(key, name, value string) messageDefinition {
	return messageDefinition{
		Key:    key,
		Name:   name,
		Kind:   matchPFCP,
		Value:  value,
		Filter: fmt.Sprintf("%s == %s", fieldPFCPMessageType, value),
	}
}

// Count calculates configured message statistics from a pcap. scopeFilter is optional and is
// combined by the API layer when the user wants to restrict statistics to selected IMSIs.
func Count(ctx context.Context, pcapFile, scopeFilter string) (*Result, error) {
	queryFilter := statsProtocolFilter
	if strings.TrimSpace(scopeFilter) != "" {
		queryFilter = fmt.Sprintf("(%s) && (%s)", scopeFilter, statsProtocolFilter)
	}

	tsharkResult, err := tshark.TsharkFields(ctx, pcapFile, queryFilter, tsharkFields)
	if err != nil {
		return nil, err
	}
	if tsharkResult.ExitCode != 0 {
		return nil, fmt.Errorf("tshark statistics failed: %s", strings.TrimSpace(tsharkResult.Stderr))
	}

	result := countFieldRows(tsharkResult.Stdout)
	result.ScopeFilter = scopeFilter
	return result, nil
}

func countFieldRows(output string) *Result {
	itemsByKey := make(map[string]*Item)
	index := newDefinitionIndex()
	result := &Result{
		Modules: make([]Module, 0, len(moduleDefinitions)),
	}

	for _, moduleDef := range moduleDefinitions {
		module := Module{
			Key:      moduleDef.Key,
			Name:     moduleDef.Name,
			Standard: moduleDef.Standard,
			Items:    make([]Item, len(moduleDef.Items)),
		}
		for i, def := range moduleDef.Items {
			module.Items[i] = Item{
				Key:    def.Key,
				Name:   def.Name,
				Filter: def.Filter,
			}
			itemsByKey[def.Key] = &module.Items[i]
			index.add(def)
		}
		result.Modules = append(result.Modules, module)
	}

	nasMMCorrections := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimRight(output, "\r\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		row := parseFieldRow(line)
		matched := make(map[string]bool)
		inc := func(def messageDefinition) {
			if matched[def.Key] {
				return
			}
			matched[def.Key] = true
			itemsByKey[def.Key].RawCount++
			if def.Kind == matchNASMM && containsValue(row.nasMMElemIDs, "0x71") {
				nasMMCorrections[def.Key] = true
			}
		}
		for _, value := range row.nasMMMessageTypes {
			for _, def := range index.nasMM[value] {
				inc(def)
			}
		}
		for _, value := range row.nasSMMessageTypes {
			for _, def := range index.nasSM[value] {
				inc(def)
			}
		}
		for _, procedure := range row.ngapProcedures {
			for _, pdu := range row.ngapPDUs {
				for _, def := range index.ngap[compoundKey(procedure, pdu)] {
					inc(def)
				}
			}
		}
		for _, value := range row.gtpv2MessageTypes {
			for _, def := range index.gtpv2[value] {
				inc(def)
			}
		}
		for _, value := range row.pfcpMessageTypes {
			for _, def := range index.pfcp[value] {
				inc(def)
			}
		}
	}

	for i := range result.Modules {
		sort.SliceStable(result.Modules[i].Items, func(a, b int) bool {
			left := result.Modules[i].Items[a]
			right := result.Modules[i].Items[b]
			return sortValueByItemKey(left.Key) < sortValueByItemKey(right.Key)
		})
		for j := range result.Modules[i].Items {
			item := &result.Modules[i].Items[j]
			if nasMMCorrections[item.Key] && item.RawCount > 0 {
				item.Correction = -1
				item.CorrectionReason = fmt.Sprintf("%s == 0x71", fieldNASMMElemID)
			}
			item.Count = item.RawCount + item.Correction
			if item.Count < 0 {
				item.Count = 0
			}
			result.Modules[i].RawTotal += item.RawCount
			result.Modules[i].FinalTotal += item.Count
		}
	}

	return result
}

func newDefinitionIndex() *definitionIndex {
	return &definitionIndex{
		nasMM: make(map[string][]messageDefinition),
		nasSM: make(map[string][]messageDefinition),
		ngap:  make(map[string][]messageDefinition),
		gtpv2: make(map[string][]messageDefinition),
		pfcp:  make(map[string][]messageDefinition),
	}
}

func (idx *definitionIndex) add(def messageDefinition) {
	switch def.Kind {
	case matchNASMM:
		idx.nasMM[def.Value] = append(idx.nasMM[def.Value], def)
	case matchNASSM:
		idx.nasSM[def.Value] = append(idx.nasSM[def.Value], def)
	case matchNGAP:
		key := compoundKey(def.Value, def.PDU)
		idx.ngap[key] = append(idx.ngap[key], def)
	case matchGTPv2:
		idx.gtpv2[def.Value] = append(idx.gtpv2[def.Value], def)
	case matchPFCP:
		idx.pfcp[def.Value] = append(idx.pfcp[def.Value], def)
	}
}

func compoundKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

func sortValueByItemKey(key string) int {
	for _, moduleDef := range moduleDefinitions {
		for _, def := range moduleDef.Items {
			if def.Key == key {
				value, ok := parseSortValue(def.Value)
				if !ok {
					return 0
				}
				return value
			}
		}
	}
	return 0
}

type fieldRow struct {
	nasMMMessageTypes []string
	nasSMMessageTypes []string
	nasMMElemIDs      []string
	ngapProcedures    []string
	ngapPDUs          []string
	gtpv2MessageTypes []string
	pfcpMessageTypes  []string
}

func parseFieldRow(line string) fieldRow {
	cols := strings.Split(line, "\t")
	for len(cols) < len(tsharkFields) {
		cols = append(cols, "")
	}

	return fieldRow{
		nasMMMessageTypes: splitValues(cols[0], true),
		nasSMMessageTypes: splitValues(cols[1], true),
		nasMMElemIDs:      splitValues(cols[2], true),
		ngapProcedures:    splitValues(cols[3], false),
		ngapPDUs:          splitValues(cols[4], false),
		gtpv2MessageTypes: splitValues(cols[5], false),
		pfcpMessageTypes:  splitValues(cols[6], false),
	}
}

func matchesDefinition(def messageDefinition, row fieldRow) bool {
	switch def.Kind {
	case matchNASMM:
		return containsValue(row.nasMMMessageTypes, def.Value)
	case matchNASSM:
		return containsValue(row.nasSMMessageTypes, def.Value)
	case matchNGAP:
		return containsValue(row.ngapProcedures, def.Value) && containsValue(row.ngapPDUs, def.PDU)
	case matchGTPv2:
		return containsValue(row.gtpv2MessageTypes, def.Value)
	case matchPFCP:
		return containsValue(row.pfcpMessageTypes, def.Value)
	default:
		return false
	}
}

func splitValues(value string, asHex bool) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';'
	})

	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		if part == "" {
			continue
		}
		if idx := strings.IndexAny(part, " \t("); idx >= 0 {
			part = part[:idx]
		}
		if asHex {
			part = normalizeHexDefinition(part)
		}
		values = append(values, part)
	}
	return values
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func normalizeHexDefinition(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "0x")
	if value == "" {
		return "0x0"
	}
	if parsed, err := strconv.ParseUint(value, 16, 16); err == nil {
		return fmt.Sprintf("0x%02x", parsed)
	}
	return "0x" + value
}

func parseSortValue(value string) (int, bool) {
	value = strings.TrimSpace(strings.ToLower(value))
	base := 10
	if strings.HasPrefix(value, "0x") {
		base = 16
		value = strings.TrimPrefix(value, "0x")
	}
	parsed, err := strconv.ParseInt(value, base, 32)
	if err != nil {
		return 0, false
	}
	return int(parsed), true
}

func displayHex(value string) string {
	return "0x" + strings.ToUpper(strings.TrimPrefix(value, "0x"))
}
