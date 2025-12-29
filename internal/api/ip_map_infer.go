package api

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"
)

// InferIPMappings analyzes packets and infers IP→NE (network element) mappings
// based on protocol-specific rules. This is a deterministic, rule-based engine
// that replaces the LLM-based annotation approach.
//
// Rules priority (applied in order):
// 1. NGAP: SCTP port 38412 → one side is AMF, other is gNB
// 2. S1AP: SCTP port 36412 → one side is MME, other is eNB
// 3. PFCP: UDP port 8805 → one side is SMF, other is UPF (based on message direction)
// 4. GTPv2-C: UDP port 2123 → SGW/PGW (direction-based inference)
// 5. GTP-U: UDP port 2152 → based on known endpoints from other protocols
func InferIPMappings(compactJSON string) []IPMapping {
	var packets []map[string]interface{}
	if err := json.Unmarshal([]byte(compactJSON), &packets); err != nil {
		log.Printf("[InferIPMappings] Failed to parse JSON: %v", err)
		return nil
	}

	if len(packets) == 0 {
		return nil
	}

	// ipRoleMap tracks IP → role with confidence
	// Higher confidence means more certain identification
	type roleInfo struct {
		Role       string
		Confidence float64
		Reason     string
	}
	ipRoleMap := make(map[string]*roleInfo)

	// Helper to update role for an IP (only if new confidence >= existing)
	updateRole := func(ip, role, reason string, confidence float64) {
		if ip == "" || ip == "?" {
			return
		}
		existing, ok := ipRoleMap[ip]
		if !ok || confidence > existing.Confidence {
			ipRoleMap[ip] = &roleInfo{
				Role:       role,
				Confidence: confidence,
				Reason:     reason,
			}
		}
	}

	// First pass: Analyze each packet for protocol-specific rules
	for _, pkt := range packets {
		layers, _ := pkt["layers"].(map[string]interface{})
		if layers == nil {
			continue
		}

		srcIP := getString(layers, "src_ip")
		dstIP := getString(layers, "dst_ip")
		srcPort := getString(layers, "src_port")
		dstPort := getString(layers, "dst_port")
		proto := strings.ToLower(getString(layers, "proto"))

		app, _ := pkt["application"].(map[string]interface{})

		// Rule 1: NGAP (SCTP port 38412)
		if app != nil && app["ngap"] != nil {
			// NGAP uses SCTP, port 38412 is the well-known AMF port
			if proto == "sctp" {
				if srcPort == "38412" {
					// Source is AMF (responds from 38412)
					updateRole(srcIP, "AMF", "NGAP: SCTP source port 38412", 0.95)
					updateRole(dstIP, "gNB", "NGAP: SCTP dest port != 38412", 0.90)
				} else if dstPort == "38412" {
					// Destination is AMF (receives on 38412)
					updateRole(dstIP, "AMF", "NGAP: SCTP dest port 38412", 0.95)
					updateRole(srcIP, "gNB", "NGAP: SCTP source port != 38412", 0.90)
				} else {
					// No well-known port, infer from message direction
					// Typically gNB → AMF for initial messages
					inferNGAPRoles(app["ngap"], srcIP, dstIP, updateRole)
				}
			}
		}

		// Rule 2: S1AP (SCTP port 36412)
		if app != nil && app["s1ap"] != nil {
			if proto == "sctp" {
				if srcPort == "36412" {
					updateRole(srcIP, "MME", "S1AP: SCTP source port 36412", 0.95)
					updateRole(dstIP, "eNB", "S1AP: SCTP dest port != 36412", 0.90)
				} else if dstPort == "36412" {
					updateRole(dstIP, "MME", "S1AP: SCTP dest port 36412", 0.95)
					updateRole(srcIP, "eNB", "S1AP: SCTP source port != 36412", 0.90)
				} else {
					inferS1APRoles(app["s1ap"], srcIP, dstIP, updateRole)
				}
			}
		}

		// Rule 3: PFCP (UDP port 8805)
		if app != nil && app["pfcp"] != nil {
			if proto == "udp" {
				// PFCP message types determine direction:
				// - Request messages (50, 52, 54, 56...) are sent from SMF to UPF
				// - Response messages (51, 53, 55, 57...) are sent from UPF to SMF
				inferPFCPRoles(app["pfcp"], srcIP, dstIP, srcPort, dstPort, updateRole)
			}
		}

		// Rule 4: GTPv2-C (UDP port 2123)
		if app != nil && app["gtpv2"] != nil {
			if proto == "udp" {
				inferGTPv2Roles(app["gtpv2"], srcIP, dstIP, srcPort, dstPort, updateRole)
			}
		}

		// Rule 5: GTP-U (UDP port 2152)
		if app != nil && app["gtp"] != nil {
			if proto == "udp" {
				// Build lookup map from current ipRoleMap
				knownRoles := make(ipRoleLookupMap)
				for ip, info := range ipRoleMap {
					knownRoles[ip] = info.Role
				}
				inferGTPURoles(srcIP, dstIP, srcPort, dstPort, knownRoles, updateRole)
			}
		}
	}

	// Convert to IPMapping slice
	result := make([]IPMapping, 0, len(ipRoleMap))
	for ip, info := range ipRoleMap {
		result = append(result, IPMapping{
			IP:         ip,
			NE:         info.Role,
			Confidence: info.Confidence,
			Reason:     info.Reason,
		})
	}

	log.Printf("[InferIPMappings] Inferred %d IP→NE mappings from %d packets", len(result), len(packets))
	for _, m := range result {
		log.Printf("[InferIPMappings]   %s → %s (conf=%.2f, reason=%s)", m.IP, m.NE, m.Confidence, m.Reason)
	}

	return result
}

// inferNGAPRoles infers gNB/AMF roles from NGAP message content
func inferNGAPRoles(ngapData interface{}, srcIP, dstIP string, updateRole func(string, string, string, float64)) {
	ngap, ok := ngapData.(map[string]interface{})
	if !ok {
		return
	}

	procedure := getString(ngap, "procedure")
	procedureCode := getString(ngap, "procedureCode")

	// InitialUEMessage (15): gNB → AMF
	// NGSetupRequest: gNB → AMF
	// DownlinkNASTransport (4): AMF → gNB
	// InitialContextSetupRequest (14): AMF → gNB

	switch {
	case procedureCode == "15" || strings.Contains(strings.ToLower(procedure), "initialuemessage"):
		updateRole(srcIP, "gNB", "NGAP: InitialUEMessage sender", 0.85)
		updateRole(dstIP, "AMF", "NGAP: InitialUEMessage receiver", 0.85)
	case procedureCode == "4" || strings.Contains(strings.ToLower(procedure), "downlinknas"):
		updateRole(srcIP, "AMF", "NGAP: DownlinkNASTransport sender", 0.85)
		updateRole(dstIP, "gNB", "NGAP: DownlinkNASTransport receiver", 0.85)
	case procedureCode == "14" || strings.Contains(strings.ToLower(procedure), "initialcontextsetup"):
		updateRole(srcIP, "AMF", "NGAP: InitialContextSetupRequest sender", 0.85)
		updateRole(dstIP, "gNB", "NGAP: InitialContextSetupRequest receiver", 0.85)
	case procedureCode == "21" || strings.Contains(strings.ToLower(procedure), "ngsetup"):
		updateRole(srcIP, "gNB", "NGAP: NGSetup sender", 0.80)
		updateRole(dstIP, "AMF", "NGAP: NGSetup receiver", 0.80)
	case procedureCode == "29" || strings.Contains(strings.ToLower(procedure), "pdusessionresourcesetup"):
		// PDUSessionResourceSetupRequest: AMF → gNB
		updateRole(srcIP, "AMF", "NGAP: PDUSessionResourceSetup sender", 0.85)
		updateRole(dstIP, "gNB", "NGAP: PDUSessionResourceSetup receiver", 0.85)
	}
}

// inferS1APRoles infers eNB/MME roles from S1AP message content
func inferS1APRoles(s1apData interface{}, srcIP, dstIP string, updateRole func(string, string, string, float64)) {
	s1ap, ok := s1apData.(map[string]interface{})
	if !ok {
		return
	}

	procedure := getString(s1ap, "procedure")
	procedureCode := getString(s1ap, "procedureCode")

	switch {
	case procedureCode == "12" || strings.Contains(strings.ToLower(procedure), "initialuemessage"):
		updateRole(srcIP, "eNB", "S1AP: InitialUEMessage sender", 0.85)
		updateRole(dstIP, "MME", "S1AP: InitialUEMessage receiver", 0.85)
	case procedureCode == "11" || strings.Contains(strings.ToLower(procedure), "downlinknas"):
		updateRole(srcIP, "MME", "S1AP: DownlinkNASTransport sender", 0.85)
		updateRole(dstIP, "eNB", "S1AP: DownlinkNASTransport receiver", 0.85)
	case procedureCode == "9" || strings.Contains(strings.ToLower(procedure), "initialcontextsetup"):
		updateRole(srcIP, "MME", "S1AP: InitialContextSetupRequest sender", 0.85)
		updateRole(dstIP, "eNB", "S1AP: InitialContextSetupRequest receiver", 0.85)
	case procedureCode == "17" || strings.Contains(strings.ToLower(procedure), "s1setup"):
		updateRole(srcIP, "eNB", "S1AP: S1Setup sender", 0.80)
		updateRole(dstIP, "MME", "S1AP: S1Setup receiver", 0.80)
	}
}

// inferPFCPRoles infers SMF/UPF roles from PFCP message types
// PFCP message types:
// - 50: Session Establishment Request (SMF → UPF)
// - 51: Session Establishment Response (UPF → SMF)
// - 52: Session Modification Request (SMF → UPF)
// - 53: Session Modification Response (UPF → SMF)
// - 54: Session Deletion Request (SMF → UPF)
// - 55: Session Deletion Response (UPF → SMF)
// - 5: Association Setup Request (usually SMF → UPF)
// - 6: Association Setup Response (usually UPF → SMF)
// - 1: Heartbeat Request
// - 2: Heartbeat Response
func inferPFCPRoles(pfcpData interface{}, srcIP, dstIP, srcPort, dstPort string, updateRole func(string, string, string, float64)) {
	pfcp, ok := pfcpData.(map[string]interface{})
	if !ok {
		return
	}

	msgTypeStr := getString(pfcp, "message_type")
	msgType, _ := strconv.Atoi(msgTypeStr)

	message := getString(pfcp, "message")

	// Port-based inference (8805 is well-known PFCP port)
	portConfidence := 0.0
	if srcPort == "8805" || dstPort == "8805" {
		portConfidence = 0.70
	}

	// Message type based inference
	switch msgType {
	case 50, 52, 54: // Requests (SMF → UPF)
		updateRole(srcIP, "SMF", "PFCP: Session Request sender", 0.90+portConfidence*0.05)
		updateRole(dstIP, "UPF", "PFCP: Session Request receiver", 0.90+portConfidence*0.05)
	case 51, 53, 55: // Responses (UPF → SMF)
		updateRole(srcIP, "UPF", "PFCP: Session Response sender", 0.90+portConfidence*0.05)
		updateRole(dstIP, "SMF", "PFCP: Session Response receiver", 0.90+portConfidence*0.05)
	case 5: // Association Setup Request
		updateRole(srcIP, "SMF", "PFCP: Association Setup Request sender", 0.80)
		updateRole(dstIP, "UPF", "PFCP: Association Setup Request receiver", 0.80)
	case 6: // Association Setup Response
		updateRole(srcIP, "UPF", "PFCP: Association Setup Response sender", 0.80)
		updateRole(dstIP, "SMF", "PFCP: Association Setup Response receiver", 0.80)
	case 1, 2: // Heartbeat - can go either direction, skip
		return
	default:
		// Use message string if available
		msgLower := strings.ToLower(message)
		if strings.Contains(msgLower, "session establishment request") ||
			strings.Contains(msgLower, "session modification request") ||
			strings.Contains(msgLower, "session deletion request") {
			updateRole(srcIP, "SMF", "PFCP: Session Request sender", 0.85)
			updateRole(dstIP, "UPF", "PFCP: Session Request receiver", 0.85)
		} else if strings.Contains(msgLower, "session establishment response") ||
			strings.Contains(msgLower, "session modification response") ||
			strings.Contains(msgLower, "session deletion response") {
			updateRole(srcIP, "UPF", "PFCP: Session Response sender", 0.85)
			updateRole(dstIP, "SMF", "PFCP: Session Response receiver", 0.85)
		}
	}
}

// inferGTPv2Roles infers SGW/PGW/MME roles from GTPv2-C messages
// GTPv2-C message types:
// - 32: Create Session Request
// - 33: Create Session Response
// - 34: Modify Bearer Request
// - 35: Modify Bearer Response
// - 36: Delete Session Request
// - 37: Delete Session Response
func inferGTPv2Roles(gtpv2Data interface{}, srcIP, dstIP, srcPort, dstPort string, updateRole func(string, string, string, float64)) {
	gtpv2, ok := gtpv2Data.(map[string]interface{})
	if !ok {
		return
	}

	msgTypeStr := getString(gtpv2, "message_type")
	msgType, _ := strconv.Atoi(msgTypeStr)

	message := getString(gtpv2, "message")
	msgLower := strings.ToLower(message)

	// Port 2123 is well-known GTPv2-C port
	portConfidence := 0.0
	if srcPort == "2123" || dstPort == "2123" {
		portConfidence = 0.05
	}

	// GTPv2-C has complex routing:
	// - Create Session Request: MME → SGW or SGW → PGW
	// - Create Session Response: PGW → SGW or SGW → MME
	// We use a combined label "SGW/PGW" when we can't distinguish

	switch msgType {
	case 32: // Create Session Request
		if strings.Contains(msgLower, "create session request") {
			// Could be MME→SGW or SGW→PGW, use combined label
			updateRole(srcIP, "SGW", "GTPv2-C: Create Session Request sender", 0.70+portConfidence)
			updateRole(dstIP, "PGW", "GTPv2-C: Create Session Request receiver", 0.70+portConfidence)
		}
	case 33: // Create Session Response
		updateRole(srcIP, "PGW", "GTPv2-C: Create Session Response sender", 0.70+portConfidence)
		updateRole(dstIP, "SGW", "GTPv2-C: Create Session Response receiver", 0.70+portConfidence)
	case 34, 36: // Modify/Delete Bearer Request
		updateRole(srcIP, "SGW", "GTPv2-C: Bearer Request sender", 0.65+portConfidence)
		updateRole(dstIP, "PGW", "GTPv2-C: Bearer Request receiver", 0.65+portConfidence)
	case 35, 37: // Modify/Delete Bearer Response
		updateRole(srcIP, "PGW", "GTPv2-C: Bearer Response sender", 0.65+portConfidence)
		updateRole(dstIP, "SGW", "GTPv2-C: Bearer Response receiver", 0.65+portConfidence)
	default:
		// Use message string for inference
		if strings.Contains(msgLower, "request") {
			// Requests typically go from SGW side
			updateRole(srcIP, "SGW", "GTPv2-C: Request sender", 0.60)
			updateRole(dstIP, "PGW", "GTPv2-C: Request receiver", 0.60)
		} else if strings.Contains(msgLower, "response") {
			updateRole(srcIP, "PGW", "GTPv2-C: Response sender", 0.60)
			updateRole(dstIP, "SGW", "GTPv2-C: Response receiver", 0.60)
		}
	}
}

// gtpuRoleLookup is an interface for looking up roles by IP
type gtpuRoleLookup interface {
	getRole(ip string) string
}

// ipRoleLookupMap implements gtpuRoleLookup using the internal roleInfo map
type ipRoleLookupMap map[string]string

func (m ipRoleLookupMap) getRole(ip string) string {
	return m[ip]
}

// inferGTPURoles infers roles from GTP-U based on already-known endpoints
// GTP-U typically runs between:
// - gNB ↔ UPF (5G)
// - eNB ↔ SGW-U (LTE)
// We use the known roles to identify endpoints and infer the other side
func inferGTPURoles(srcIP, dstIP, srcPort, dstPort string, knownRoles ipRoleLookupMap, updateRole func(string, string, string, float64)) {
	// Check if either IP is already known
	srcRole := knownRoles.getRole(srcIP)
	dstRole := knownRoles.getRole(dstIP)

	// Port 2152 is well-known GTP-U port
	if srcPort == "2152" || dstPort == "2152" {
		// Infer based on known roles
		if srcRole == "gNB" {
			updateRole(dstIP, "UPF", "GTP-U: opposite of known gNB", 0.75)
		} else if srcRole == "UPF" {
			updateRole(dstIP, "gNB", "GTP-U: opposite of known UPF", 0.75)
		} else if srcRole == "eNB" {
			updateRole(dstIP, "SGW", "GTP-U: opposite of known eNB", 0.75)
		} else if srcRole == "SGW" {
			updateRole(dstIP, "eNB", "GTP-U: opposite of known SGW", 0.75)
		}

		if dstRole == "gNB" {
			updateRole(srcIP, "UPF", "GTP-U: opposite of known gNB", 0.75)
		} else if dstRole == "UPF" {
			updateRole(srcIP, "gNB", "GTP-U: opposite of known UPF", 0.75)
		} else if dstRole == "eNB" {
			updateRole(srcIP, "SGW", "GTP-U: opposite of known eNB", 0.75)
		} else if dstRole == "SGW" {
			updateRole(srcIP, "eNB", "GTP-U: opposite of known SGW", 0.75)
		}

		// If neither is known, use combined label
		if srcRole == "" && dstRole == "" {
			// Can't determine direction, use generic labels
			// This is a fallback and may not be accurate
			updateRole(srcIP, "RAN/UPF", "GTP-U: endpoint (unknown direction)", 0.50)
			updateRole(dstIP, "RAN/UPF", "GTP-U: endpoint (unknown direction)", 0.50)
		}
	}
}

// InferIPMappingsWithEmptyStages calls InferIPMappings and returns a FlowAnnotationsV1
// with the inferred ip_map and empty stages (no stage grouping).
func InferIPMappingsWithEmptyStages(compactJSON string) *FlowAnnotationsV1 {
	ipMappings := InferIPMappings(compactJSON)
	if ipMappings == nil {
		ipMappings = []IPMapping{}
	}

	return &FlowAnnotationsV1{
		Version:  "flow_annotations_v1",
		FlowName: "信令流程图",
		IPMap:    ipMappings,
		Stages:   []FlowStage{}, // Empty stages - no stage grouping
	}
}

