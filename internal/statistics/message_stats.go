package statistics

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"gitee.com/yangdadayyds/uepcap/internal/analysislimit"
	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

const (
	fieldNASMMMessageType = "nas_5gs.mm.message_type"
	fieldNASSMMessageType = "nas_5gs.sm.message_type"
	fieldNASMMElemID      = "nas_5gs.mm.elem_id"
	fieldNGAPProcedure    = "ngap.procedureCode"
	fieldNGAPPDU          = "ngap.NGAP_PDU"
	fieldS1APProcedure    = "s1ap.procedureCode"
	fieldS1APPDU          = "s1ap.S1AP_PDU"
	fieldGTPv2MessageType = "gtpv2.message_type"
	fieldPFCPMessageType  = "pfcp.msg_type"
)

const statsProtocolFilter = "nas-5gs or ngap or s1ap or gtpv2 or pfcp"

var tsharkFields = []string{
	fieldNASMMMessageType,
	fieldNASSMMessageType,
	fieldNASMMElemID,
	fieldNGAPProcedure,
	fieldNGAPPDU,
	fieldGTPv2MessageType,
	fieldPFCPMessageType,
	fieldS1APProcedure,
	fieldS1APPDU,
}

type matchKind string

const (
	matchNASMM matchKind = "nas_mm"
	matchNASSM matchKind = "nas_sm"
	matchNGAP  matchKind = "ngap"
	matchS1AP  matchKind = "s1ap"
	matchGTPv2 matchKind = "gtpv2"
	matchPFCP  matchKind = "pfcp"
)

// Result is the full message statistics response.
type Result struct {
	ScopeFilter string   `json:"scope_filter,omitempty"`
	Truncated   bool     `json:"truncated,omitempty"`
	RowLimit    int      `json:"row_limit,omitempty"`
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
	Module string
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
	s1ap  map[string][]messageDefinition
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
			nasMM("service-reject", "SERVICE REJECT", "0x4D"),
			nasMM("service-accept", "SERVICE ACCEPT", "0x4E"),
			nasMM("control-plane-service-request", "CONTROL PLANE SERVICE REQUEST", "0x4F"),
			nasMM("configuration-update-command", "CONFIGURATION UPDATE COMMAND", "0x54"),
			nasMM("configuration-update-complete", "CONFIGURATION UPDATE COMPLETE", "0x55"),
			nasMM("authentication-request", "AUTHENTICATION REQUEST", "0x56"),
			nasMM("authentication-response", "AUTHENTICATION RESPONSE", "0x57"),
			nasMM("authentication-reject", "AUTHENTICATION REJECT", "0x58"),
			nasMM("authentication-failure", "AUTHENTICATION FAILURE", "0x59"),
			nasMM("authentication-result", "AUTHENTICATION RESULT", "0x5A"),
			nasMM("identity-request", "IDENTITY REQUEST", "0x5B"),
			nasMM("identity-response", "IDENTITY RESPONSE", "0x5C"),
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
			ngap("ng-setup-request", "NG Setup Request", "21", "0"),
			ngap("ng-setup-response", "NG Setup Response", "21", "1"),
			ngap("ng-setup-failure", "NG Setup Failure", "21", "2"),
			ngap("paging", "Paging", "24", "0"),
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
			ngap("ue-radio-capability-info-indication", "UE Radio Capability Info Indication", "44", "0"),
			ngap("error-indication", "Error Indication", "9", "0"),
		},
	},
	{
		Key:      "s1ap",
		Name:     "S1AP消息",
		Standard: "TS 36.413",
		Items: []messageDefinition{
			s1ap("handover-required", "Handover Required", "0", "0"),
			s1ap("handover-command", "Handover Command", "0", "1"),
			s1ap("handover-preparation-failure", "Handover Preparation Failure", "0", "2"),
			s1ap("handover-request", "Handover Request", "1", "0"),
			s1ap("handover-request-acknowledge", "Handover Request Acknowledge", "1", "1"),
			s1ap("handover-failure", "Handover Failure", "1", "2"),
			s1ap("handover-notify", "Handover Notify", "2", "0"),
			s1ap("path-switch-request", "Path Switch Request", "3", "0"),
			s1ap("path-switch-request-acknowledge", "Path Switch Request Acknowledge", "3", "1"),
			s1ap("path-switch-request-failure", "Path Switch Request Failure", "3", "2"),
			s1ap("e-rab-setup-request", "E-RAB Setup Request", "5", "0"),
			s1ap("e-rab-setup-response", "E-RAB Setup Response", "5", "1"),
			s1ap("e-rab-setup-failure", "E-RAB Setup Failure", "5", "2"),
			s1ap("e-rab-modify-request", "E-RAB Modify Request", "6", "0"),
			s1ap("e-rab-modify-response", "E-RAB Modify Response", "6", "1"),
			s1ap("e-rab-modify-failure", "E-RAB Modify Failure", "6", "2"),
			s1ap("e-rab-release-command", "E-RAB Release Command", "7", "0"),
			s1ap("e-rab-release-response", "E-RAB Release Response", "7", "1"),
			s1ap("e-rab-release-indication", "E-RAB Release Indication", "8", "0"),
			s1ap("initial-context-setup-request", "Initial Context Setup Request", "9", "0"),
			s1ap("initial-context-setup-response", "Initial Context Setup Response", "9", "1"),
			s1ap("initial-context-setup-failure", "Initial Context Setup Failure", "9", "2"),
			s1ap("paging", "Paging", "10", "0"),
			s1ap("downlink-nas-transport", "Downlink NAS Transport", "11", "0"),
			s1ap("initial-ue-message", "Initial UE Message", "12", "0"),
			s1ap("uplink-nas-transport", "Uplink NAS Transport", "13", "0"),
			s1ap("reset", "Reset", "14", "0"),
			s1ap("reset-acknowledge", "Reset Acknowledge", "14", "1"),
			s1ap("error-indication", "Error Indication", "15", "0"),
			s1ap("nas-non-delivery-indication", "NAS Non Delivery Indication", "16", "0"),
			s1ap("s1-setup-request", "S1 Setup Request", "17", "0"),
			s1ap("s1-setup-response", "S1 Setup Response", "17", "1"),
			s1ap("s1-setup-failure", "S1 Setup Failure", "17", "2"),
			s1ap("ue-context-release-request", "UE Context Release Request", "18", "0"),
			s1ap("ue-context-modification-request", "UE Context Modification Request", "21", "0"),
			s1ap("ue-context-modification-response", "UE Context Modification Response", "21", "1"),
			s1ap("ue-context-modification-failure", "UE Context Modification Failure", "21", "2"),
			s1ap("ue-capability-info-indication", "UE Capability Info Indication", "22", "0"),
			s1ap("ue-context-release-command", "UE Context Release Command", "23", "0"),
			s1ap("ue-context-release-complete", "UE Context Release Complete", "23", "1"),
			s1ap("enb-configuration-update", "eNB Configuration Update", "29", "0"),
			s1ap("enb-configuration-update-acknowledge", "eNB Configuration Update Acknowledge", "29", "1"),
			s1ap("enb-configuration-update-failure", "eNB Configuration Update Failure", "29", "2"),
			s1ap("mme-configuration-update", "MME Configuration Update", "30", "0"),
			s1ap("mme-configuration-update-acknowledge", "MME Configuration Update Acknowledge", "30", "1"),
			s1ap("mme-configuration-update-failure", "MME Configuration Update Failure", "30", "2"),
			s1ap("write-replace-warning-request", "Write Replace Warning Request", "36", "0"),
			s1ap("write-replace-warning-response", "Write Replace Warning Response", "36", "1"),
			s1ap("kill-request", "Kill Request", "43", "0"),
			s1ap("kill-response", "Kill Response", "43", "1"),
			s1ap("enb-configuration-transfer", "eNB Configuration Transfer", "40", "0"),
			s1ap("mme-configuration-transfer", "MME Configuration Transfer", "41", "0"),
			s1ap("e-rab-modification-indication", "E-RAB Modification Indication", "50", "0"),
			s1ap("e-rab-modification-confirm", "E-RAB Modification Confirm", "50", "1"),
			s1ap("reroute-nas-request", "Reroute NAS Request", "52", "0"),
			s1ap("ue-context-modification-indication", "UE Context Modification Indication", "53", "0"),
			s1ap("ue-context-modification-confirm", "UE Context Modification Confirm", "53", "1"),
			s1ap("ue-context-modification-indication-failure", "UE Context Modification Indication Failure", "53", "2"),
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
			gtpv2("create-bearer-response", "Create Bearer Response", "96"),
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

func s1ap(key, name, procedure, pdu string) messageDefinition {
	return messageDefinition{
		Key:    key,
		Name:   name,
		Kind:   matchS1AP,
		Value:  procedure,
		PDU:    pdu,
		Filter: fmt.Sprintf("(%s == %s) && (%s == %s)", fieldS1APProcedure, procedure, fieldS1APPDU, pdu),
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

	limit := analysislimit.MaxRows("UEPCAP_STATS_ANALYSIS_MAX_ROWS")
	result, itemsByKey, index := newCountResult()
	rowCount := 0
	truncated := false
	tsharkResult, err := tshark.TsharkFieldsStream(ctx, pcapFile, queryFilter, tsharkFields, func(line string) error {
		if strings.TrimSpace(line) == "" {
			return nil
		}
		if limit > 0 && rowCount >= limit {
			truncated = true
			return errStatsRowLimitReached
		}
		countFieldLine(line, itemsByKey, index)
		rowCount++
		return nil
	})
	if errors.Is(err, errStatsRowLimitReached) {
		finalizeCountResult(result)
		result.ScopeFilter = scopeFilter
		result.Truncated = true
		result.RowLimit = limit
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	if tsharkResult.ExitCode != 0 {
		return nil, fmt.Errorf("tshark statistics failed: %s", strings.TrimSpace(tsharkResult.Stderr))
	}

	finalizeCountResult(result)
	result.ScopeFilter = scopeFilter
	if truncated {
		result.Truncated = true
		result.RowLimit = limit
	}
	return result, nil
}

var errStatsRowLimitReached = errors.New("statistics row limit reached")

func countFieldRows(output string) *Result {
	result, itemsByKey, index := newCountResult()
	for _, line := range strings.Split(strings.TrimRight(output, "\r\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		countFieldLine(line, itemsByKey, index)
	}
	finalizeCountResult(result)
	return result
}

func newCountResult() (*Result, map[string]*Item, *definitionIndex) {
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
			def.Module = moduleDef.Key
			module.Items[i] = Item{
				Key:    def.Key,
				Name:   def.Name,
				Filter: def.Filter,
			}
			itemsByKey[definitionItemKey(def)] = &module.Items[i]
			index.add(def)
		}
		result.Modules = append(result.Modules, module)
	}
	return result, itemsByKey, index
}

func countFieldLine(line string, itemsByKey map[string]*Item, index *definitionIndex) {
	row := parseFieldRow(line)
	matched := make(map[string]bool)
	inc := func(def messageDefinition, dedupe bool) {
		key := definitionItemKey(def)
		if dedupe && matched[key] {
			return
		}
		matched[key] = true
		itemsByKey[key].RawCount++
	}
	for _, value := range row.nasMMMessageTypes {
		for _, def := range index.nasMM[value] {
			inc(def, true)
		}
	}
	for _, value := range row.nasSMMessageTypes {
		for _, def := range index.nasSM[value] {
			inc(def, true)
		}
	}
	for _, pair := range procedurePDUPairs(row.ngapProcedures, row.ngapPDUs) {
		for _, def := range index.ngap[compoundKey(pair.procedure, pair.pdu)] {
			inc(def, false)
		}
	}
	for _, pair := range procedurePDUPairs(row.s1apProcedures, row.s1apPDUs) {
		for _, def := range index.s1ap[compoundKey(pair.procedure, pair.pdu)] {
			inc(def, false)
		}
	}
	for _, value := range row.gtpv2MessageTypes {
		for _, def := range index.gtpv2[value] {
			inc(def, true)
		}
	}
	for _, value := range row.pfcpMessageTypes {
		for _, def := range index.pfcp[value] {
			inc(def, true)
		}
	}
}

func finalizeCountResult(result *Result) {
	for i := range result.Modules {
		moduleKey := result.Modules[i].Key
		sort.SliceStable(result.Modules[i].Items, func(a, b int) bool {
			left := result.Modules[i].Items[a]
			right := result.Modules[i].Items[b]
			return sortValueByModuleItemKey(moduleKey, left.Key) < sortValueByModuleItemKey(moduleKey, right.Key)
		})
		for j := range result.Modules[i].Items {
			item := &result.Modules[i].Items[j]
			item.Count = item.RawCount + item.Correction
			if item.Count < 0 {
				item.Count = 0
			}
			result.Modules[i].RawTotal += item.RawCount
			result.Modules[i].FinalTotal += item.Count
		}
	}
}

func definitionItemKey(def messageDefinition) string {
	return compoundKey(def.Module, def.Key)
}

func newDefinitionIndex() *definitionIndex {
	return &definitionIndex{
		nasMM: make(map[string][]messageDefinition),
		nasSM: make(map[string][]messageDefinition),
		ngap:  make(map[string][]messageDefinition),
		s1ap:  make(map[string][]messageDefinition),
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
	case matchS1AP:
		key := compoundKey(def.Value, def.PDU)
		idx.s1ap[key] = append(idx.s1ap[key], def)
	case matchGTPv2:
		idx.gtpv2[def.Value] = append(idx.gtpv2[def.Value], def)
	case matchPFCP:
		idx.pfcp[def.Value] = append(idx.pfcp[def.Value], def)
	}
}

func compoundKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

func sortValueByModuleItemKey(moduleKey, itemKey string) int {
	for _, moduleDef := range moduleDefinitions {
		if moduleDef.Key != moduleKey {
			continue
		}
		for _, def := range moduleDef.Items {
			if def.Key == itemKey {
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
	s1apProcedures    []string
	s1apPDUs          []string
}

type procedurePDUPair struct {
	procedure string
	pdu       string
}

func procedurePDUPairs(procedures, pdus []string) []procedurePDUPair {
	count := max(len(procedures), len(pdus))
	pairs := make([]procedurePDUPair, 0, count)
	for i := 0; i < count; i++ {
		procedure := indexedFieldValue(procedures, i)
		if procedure == "" {
			continue
		}
		pairs = append(pairs, procedurePDUPair{
			procedure: procedure,
			pdu:       indexedFieldValue(pdus, i),
		})
	}
	return pairs
}

func indexedFieldValue(values []string, index int) string {
	if index >= 0 && index < len(values) && values[index] != "" {
		return values[index]
	}
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func parseFieldRow(line string) fieldRow {
	cols := strings.Split(line, "\t")
	for len(cols) < len(tsharkFields) {
		cols = append(cols, "")
	}
	nasMMMessageTypes, nasSMMessageTypes := parseNASMessageTypes(cols[0], cols[1])

	return fieldRow{
		nasMMMessageTypes: nasMMMessageTypes,
		nasSMMessageTypes: nasSMMessageTypes,
		nasMMElemIDs:      splitValues(cols[2], true),
		ngapProcedures:    splitValues(cols[3], false),
		ngapPDUs:          splitValues(cols[4], false),
		gtpv2MessageTypes: splitValues(cols[5], false),
		pfcpMessageTypes:  splitValues(cols[6], false),
		s1apProcedures:    splitValues(cols[7], false),
		s1apPDUs:          splitValues(cols[8], false),
	}
}

func parseNASMessageTypes(mmField, smField string) ([]string, []string) {
	return firstSplitValue(mmField, true), firstSplitValue(smField, true)
}

func firstSplitValue(value string, asHex bool) []string {
	values := splitValues(value, asHex)
	if len(values) == 0 {
		return nil
	}
	return values[:1]
}

func matchesDefinition(def messageDefinition, row fieldRow) bool {
	switch def.Kind {
	case matchNASMM:
		return containsValue(row.nasMMMessageTypes, def.Value)
	case matchNASSM:
		return containsValue(row.nasSMMessageTypes, def.Value)
	case matchNGAP:
		return containsValue(row.ngapProcedures, def.Value) && containsValue(row.ngapPDUs, def.PDU)
	case matchS1AP:
		return containsValue(row.s1apProcedures, def.Value) && containsValue(row.s1apPDUs, def.PDU)
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
