package api

import (
	"strings"
	"testing"
)

// TestBuildDeterministicMermaid_IPKeyed tests that participants are keyed by IP
// and message direction follows src_ip → dst_ip.
func TestBuildDeterministicMermaid_IPKeyed(t *testing.T) {
	// Test case: 2 AMF IPs, 1 SMF IP, 1 unknown IP
	// Packets flow between different IPs
	inputJSON := `[
		{
			"frame": {"number": "1001", "time": "0.0"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "sctp"},
			"application": {"ngap": {"procedure": "InitialUEMessage"}}
		},
		{
			"frame": {"number": "1002", "time": "0.1"},
			"layers": {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "proto": "sctp"},
			"application": {"ngap": {"procedure": "DownlinkNASTransport"}}
		},
		{
			"frame": {"number": "1003", "time": "0.2"},
			"layers": {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "proto": "udp"},
			"application": {"pfcp": {"message": "Session Establishment Request"}}
		},
		{
			"frame": {"number": "1004", "time": "0.3"},
			"layers": {"src_ip": "10.0.0.4", "dst_ip": "10.0.0.3", "proto": "udp"},
			"application": {"pfcp": {"message": "Session Establishment Response"}}
		},
		{
			"frame": {"number": "1005", "time": "0.4"},
			"layers": {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.2", "proto": "tcp"},
			"application": {}
		}
	]`

	// Annotations: partial coverage (only some IPs mapped)
	annotations := &FlowAnnotationsV1{
		Version:  "flow_annotations_v1",
		FlowName: "Test Flow",
		IPMap: []IPMapping{
			{IP: "10.0.0.1", NE: "gNB"},
			{IP: "10.0.0.2", NE: "AMF"},
			{IP: "10.0.0.3", NE: "SMF"},
			// 10.0.0.4 is not mapped (should appear as Unknown/raw IP)
			// 10.0.0.5 is not mapped (should appear as Unknown/raw IP)
		},
	}

	mermaid := buildDeterministicMermaid(inputJSON, "Test Flow", annotations, nil)

	// Verify basic structure
	if !strings.Contains(mermaid, "sequenceDiagram") {
		t.Error("Expected sequenceDiagram header")
	}
	if !strings.Contains(mermaid, "autonumber") {
		t.Error("Expected autonumber")
	}

	// Verify participant ordering: gNB → AMF → SMF → unknown IPs
	// gNB should come before AMF
	gnbIdx := strings.Index(mermaid, "gNB(10.0.0.1)")
	amfIdx := strings.Index(mermaid, "AMF(10.0.0.2)")
	smfIdx := strings.Index(mermaid, "SMF(10.0.0.3)")

	if gnbIdx == -1 {
		t.Error("Expected gNB(10.0.0.1) participant")
	}
	if amfIdx == -1 {
		t.Error("Expected AMF(10.0.0.2) participant")
	}
	if smfIdx == -1 {
		t.Error("Expected SMF(10.0.0.3) participant")
	}

	// gNB should appear before AMF in participant list
	if gnbIdx > amfIdx {
		t.Error("Expected gNB to appear before AMF in participant list")
	}
	// AMF should appear before SMF
	if amfIdx > smfIdx {
		t.Error("Expected AMF to appear before SMF in participant list")
	}

	// Verify unknown IPs are shown as raw IP (not port-inferred role)
	if !strings.Contains(mermaid, "10.0.0.4") {
		t.Error("Expected unmapped IP 10.0.0.4 to appear as raw IP")
	}
	if !strings.Contains(mermaid, "10.0.0.5") {
		t.Error("Expected unmapped IP 10.0.0.5 to appear as raw IP")
	}

	// Unknown IPs should NOT be named like "SMF/UPF(10.0.0.4)" from port inference
	if strings.Contains(mermaid, "SMF/UPF(10.0.0.4)") {
		t.Error("Port-based inference should not be used for unknown IPs")
	}

	// Verify message directions follow src_ip → dst_ip
	// We can't easily parse the P1->>P2 format, but we can verify the messages exist
	lines := strings.Split(mermaid, "\n")
	messageCount := 0
	for _, line := range lines {
		if strings.Contains(line, "->>") && strings.Contains(line, ":") {
			messageCount++
		}
	}
	if messageCount != 5 {
		t.Errorf("Expected 5 message arrows, got %d", messageCount)
	}

	t.Logf("Generated Mermaid:\n%s", mermaid)
}

// TestBuildDeterministicMermaid_MultipleIPsSameRole tests numbering when
// multiple IPs have the same role (e.g., AMF1, AMF2).
func TestBuildDeterministicMermaid_MultipleIPsSameRole(t *testing.T) {
	inputJSON := `[
		{
			"frame": {"number": "1001", "time": "0.0"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "proto": "sctp"},
			"application": {"ngap": {"procedure": "Test1"}}
		},
		{
			"frame": {"number": "1002", "time": "0.1"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "proto": "sctp"},
			"application": {"ngap": {"procedure": "Test2"}}
		}
	]`

	// Two AMF IPs
	annotations := &FlowAnnotationsV1{
		Version:  "flow_annotations_v1",
		FlowName: "Multi AMF Test",
		IPMap: []IPMapping{
			{IP: "10.0.0.1", NE: "gNB"},
			{IP: "10.0.0.2", NE: "AMF"},
			{IP: "10.0.0.3", NE: "AMF"}, // Second AMF
		},
	}

	mermaid := buildDeterministicMermaid(inputJSON, "Multi AMF Test", annotations, nil)

	// Should have AMF1 and AMF2 (numbered because multiple AMFs)
	if !strings.Contains(mermaid, "AMF1(10.0.0.2)") {
		t.Error("Expected AMF1(10.0.0.2) for first AMF")
	}
	if !strings.Contains(mermaid, "AMF2(10.0.0.3)") {
		t.Error("Expected AMF2(10.0.0.3) for second AMF")
	}

	// gNB should not be numbered (only one gNB)
	if strings.Contains(mermaid, "gNB1(") {
		t.Error("Single gNB should not be numbered")
	}
	if !strings.Contains(mermaid, "gNB(10.0.0.1)") {
		t.Error("Expected gNB(10.0.0.1) without numbering")
	}

	t.Logf("Generated Mermaid:\n%s", mermaid)
}

// TestBuildDeterministicMermaid_NoAnnotations tests fallback when no annotations provided.
func TestBuildDeterministicMermaid_NoAnnotations(t *testing.T) {
	inputJSON := `[
		{
			"frame": {"number": "1001", "time": "0.0"},
			"layers": {"src_ip": "192.168.1.1", "dst_ip": "192.168.1.2", "proto": "sctp"},
			"application": {"ngap": {"procedure": "TestProc"}}
		}
	]`

	// No annotations - IPs should appear as raw IPs
	mermaid := buildDeterministicMermaid(inputJSON, "No Annotations Test", nil, nil)

	// Should have raw IPs as participants
	if !strings.Contains(mermaid, "192.168.1.1") {
		t.Error("Expected raw IP 192.168.1.1 as participant")
	}
	if !strings.Contains(mermaid, "192.168.1.2") {
		t.Error("Expected raw IP 192.168.1.2 as participant")
	}

	t.Logf("Generated Mermaid:\n%s", mermaid)
}

// TestBuildDeterministicMermaid_EmptyPackets tests handling of empty input.
func TestBuildDeterministicMermaid_EmptyPackets(t *testing.T) {
	mermaid := buildDeterministicMermaid("[]", "Empty Test", nil, nil)

	if !strings.Contains(mermaid, "sequenceDiagram") {
		t.Error("Expected sequenceDiagram header even for empty input")
	}
	if !strings.Contains(mermaid, "autonumber") {
		t.Error("Expected autonumber even for empty input")
	}
}

// TestBuildDeterministicMermaid_InvalidJSON tests handling of invalid JSON.
func TestBuildDeterministicMermaid_InvalidJSON(t *testing.T) {
	mermaid := buildDeterministicMermaid("not valid json", "Invalid Test", nil, nil)

	// Should return minimal valid mermaid
	if !strings.Contains(mermaid, "sequenceDiagram") {
		t.Error("Expected sequenceDiagram header for invalid JSON")
	}
}

// TestBuildDeterministicMermaid_DirectionConsistency verifies that message
// direction strictly follows src_ip → dst_ip regardless of port.
func TestBuildDeterministicMermaid_DirectionConsistency(t *testing.T) {
	// Both packets on SCTP/38412 but different directions
	inputJSON := `[
		{
			"frame": {"number": "1001", "time": "0.0"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "38412", "dst_port": "38412", "proto": "sctp"},
			"application": {"ngap": {"procedure": "Request"}}
		},
		{
			"frame": {"number": "1002", "time": "0.1"},
			"layers": {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": "38412", "dst_port": "38412", "proto": "sctp"},
			"application": {"ngap": {"procedure": "Response"}}
		}
	]`

	annotations := &FlowAnnotationsV1{
		Version:  "flow_annotations_v1",
		FlowName: "Direction Test",
		IPMap: []IPMapping{
			{IP: "10.0.0.1", NE: "gNB"},
			{IP: "10.0.0.2", NE: "AMF"},
		},
	}

	mermaid := buildDeterministicMermaid(inputJSON, "Direction Test", annotations, nil)

	// Parse the mermaid to find message lines
	lines := strings.Split(mermaid, "\n")
	var messageLines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "->>") && strings.Contains(trimmed, ":") {
			messageLines = append(messageLines, trimmed)
		}
	}

	if len(messageLines) != 2 {
		t.Fatalf("Expected 2 message lines, got %d", len(messageLines))
	}

	// First message should be from P1 (gNB) to P2 (AMF)
	// Second message should be from P2 (AMF) to P1 (gNB)
	// P1 = gNB (first in role order), P2 = AMF
	if !strings.HasPrefix(messageLines[0], "P1->>P2:") {
		t.Errorf("First message should be P1->>P2, got: %s", messageLines[0])
	}
	if !strings.HasPrefix(messageLines[1], "P2->>P1:") {
		t.Errorf("Second message should be P2->>P1, got: %s", messageLines[1])
	}

	t.Logf("Message lines: %v", messageLines)
}

// TestGetRoleGroupIndex tests the role ordering function.
func TestGetRoleGroupIndex(t *testing.T) {
	tests := []struct {
		role     string
		expected int
	}{
		{"gNB", 0},
		{"eNB", 1},
		{"AMF", 2},
		{"MME", 3},
		{"SMF", 4},
		{"PGW", 5},
		{"UPF", 6},
		{"SGW", 7},
		{"Unknown", 8}, // Should be len(roleOrder)
		{"PCRF", 8},    // Unknown role
		{"", 8},        // Empty role
	}

	for _, tc := range tests {
		got := getRoleGroupIndex(tc.role)
		if got != tc.expected {
			t.Errorf("getRoleGroupIndex(%q) = %d, want %d", tc.role, got, tc.expected)
		}
	}
}

// TestBuildDeterministicMermaid_PFCPSessionDNN tests that PFCP session messages
// (msg_type 50-57) include DNN labels extracted from Network Instance IEs.
func TestBuildDeterministicMermaid_PFCPSessionDNN(t *testing.T) {
	// Packet 1: PFCP Session Establishment Request (msg_type=50)
	// Contains Network Instance "ctnet" and F-SEID with SEID "0x1234"
	// Packet 2: PFCP Session Establishment Response (msg_type=51)
	// Header SEID is "0x1234" (from request), response contains F-SEID with SEID "0x5678" (UPF side)
	// Packet 3: PFCP Session Modification Request (msg_type=52)
	// Header SEID is "0x5678" (UPF side) - should inherit DNN "ctnet"
	inputJSON := `[
		{
			"frame": {"number": "1001", "time": "0.0"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "8805", "dst_port": "8805", "proto": "udp"},
			"application": {
				"pfcp": {
					"message_type": "50",
					"message": "Session Establishment Request",
					"seid": "0",
					"ies": {
						"Create PDR": {
							"PDI": {
								"Network Instance": "ctnet"
							}
						},
						"F-SEID": {
							"SEID": "0x1234",
							"IPv4": "10.0.0.1"
						}
					}
				}
			}
		},
		{
			"frame": {"number": "1002", "time": "0.1"},
			"layers": {"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": "8805", "dst_port": "8805", "proto": "udp"},
			"application": {
				"pfcp": {
					"message_type": "51",
					"message": "Session Establishment Response",
					"seid": "0x1234",
					"ies": {
						"F-SEID": {
							"SEID": "0x5678",
							"IPv4": "10.0.0.2"
						}
					}
				}
			}
		},
		{
			"frame": {"number": "1003", "time": "0.2"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "8805", "dst_port": "8805", "proto": "udp"},
			"application": {
				"pfcp": {
					"message_type": "52",
					"message": "Session Modification Request",
					"seid": "0x5678"
				}
			}
		}
	]`

	mermaid := buildDeterministicMermaid(inputJSON, "PFCP DNN Test", nil, nil)

	// Check that Session Establishment Request contains DNN
	if !strings.Contains(mermaid, "Session Establishment Request（ctnet）") {
		t.Errorf("Expected Session Establishment Request to contain DNN label.\nMermaid:\n%s", mermaid)
	}

	// Check that Session Establishment Response contains DNN (inherited from request via SEID)
	if !strings.Contains(mermaid, "Session Establishment Response（ctnet）") {
		t.Errorf("Expected Session Establishment Response to contain DNN label.\nMermaid:\n%s", mermaid)
	}

	// Check that Session Modification Request contains DNN (inherited via UPF SEID)
	if !strings.Contains(mermaid, "Session Modification Request（ctnet）") {
		t.Errorf("Expected Session Modification Request to contain DNN label.\nMermaid:\n%s", mermaid)
	}
}

// TestBuildDeterministicMermaid_PFCPMultipleDNNs tests that multiple DNNs
// in the same PFCP packet are displayed as comma-separated list.
func TestBuildDeterministicMermaid_PFCPMultipleDNNs(t *testing.T) {
	// Packet with two different Network Instances (e.g., multiple FAR/PDR)
	inputJSON := `[
		{
			"frame": {"number": "2001", "time": "0.0"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "8805", "dst_port": "8805", "proto": "udp"},
			"application": {
				"pfcp": {
					"message_type": "50",
					"message": "Session Establishment Request",
					"seid": "0",
					"ies": {
						"Create PDR 1": {
							"PDI": {
								"Network Instance": "internet"
							}
						},
						"Create PDR 2": {
							"PDI": {
								"Network Instance": "ctnet"
							}
						},
						"F-SEID": {
							"SEID": "0xABCD"
						}
					}
				}
			}
		}
	]`

	mermaid := buildDeterministicMermaid(inputJSON, "Multiple DNNs Test", nil, nil)

	// DNNs should be sorted alphabetically: ctnet,internet
	if !strings.Contains(mermaid, "Session Establishment Request（ctnet,internet）") {
		t.Errorf("Expected multiple DNNs to be sorted and comma-separated.\nMermaid:\n%s", mermaid)
	}
}

// TestBuildDeterministicMermaid_PFCPNonSessionNoDNN tests that non-session PFCP messages
// (like Heartbeat, Association) do NOT get DNN labels.
func TestBuildDeterministicMermaid_PFCPNonSessionNoDNN(t *testing.T) {
	inputJSON := `[
		{
			"frame": {"number": "3001", "time": "0.0"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "8805", "dst_port": "8805", "proto": "udp"},
			"application": {
				"pfcp": {
					"message_type": "5",
					"message": "Association Setup Request"
				}
			}
		},
		{
			"frame": {"number": "3002", "time": "0.1"},
			"layers": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": "8805", "dst_port": "8805", "proto": "udp"},
			"application": {
				"pfcp": {
					"message_type": "1",
					"message": "Heartbeat Request"
				}
			}
		}
	]`

	mermaid := buildDeterministicMermaid(inputJSON, "Non-Session PFCP Test", nil, nil)

	// Non-session messages should NOT have DNN labels (no full-width parentheses)
	if strings.Contains(mermaid, "Association Setup Request（") {
		t.Errorf("Association Setup Request should NOT have DNN label.\nMermaid:\n%s", mermaid)
	}
	if strings.Contains(mermaid, "Heartbeat Request（") {
		t.Errorf("Heartbeat Request should NOT have DNN label.\nMermaid:\n%s", mermaid)
	}
}

// TestExtractPFCPSeidsFromPacket tests the SEID extraction helper function.
func TestExtractPFCPSeidsFromPacket(t *testing.T) {
	tests := []struct {
		name     string
		pfcpInfo map[string]interface{}
		expected []string
	}{
		{
			name: "header SEID only",
			pfcpInfo: map[string]interface{}{
				"seid": "0x1234",
			},
			expected: []string{"0x1234"},
		},
		{
			name: "header SEID zero should be ignored",
			pfcpInfo: map[string]interface{}{
				"seid": "0",
			},
			expected: []string{},
		},
		{
			name: "F-SEID in ies",
			pfcpInfo: map[string]interface{}{
				"seid": "0",
				"ies": map[string]interface{}{
					"F-SEID": map[string]interface{}{
						"SEID": "0xABCD",
						"IPv4": "10.0.0.1",
					},
				},
			},
			expected: []string{"0xABCD"},
		},
		{
			name: "multiple SEIDs",
			pfcpInfo: map[string]interface{}{
				"seid": "0x1111",
				"ies": map[string]interface{}{
					"F-SEID": map[string]interface{}{
						"SEID": "0x2222",
					},
				},
			},
			expected: []string{"0x1111", "0x2222"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPFCPSeidsFromPacket(tc.pfcpInfo)
			if len(got) != len(tc.expected) {
				t.Errorf("extractPFCPSeidsFromPacket() got %v, want %v", got, tc.expected)
				return
			}
			for i, v := range got {
				if v != tc.expected[i] {
					t.Errorf("extractPFCPSeidsFromPacket()[%d] = %q, want %q", i, v, tc.expected[i])
				}
			}
		})
	}
}

// TestExtractPFCPDnnsFromPacket tests the DNN extraction helper function.
func TestExtractPFCPDnnsFromPacket(t *testing.T) {
	tests := []struct {
		name     string
		pfcpInfo map[string]interface{}
		expected []string
	}{
		{
			name: "single Network Instance",
			pfcpInfo: map[string]interface{}{
				"ies": map[string]interface{}{
					"Create PDR": map[string]interface{}{
						"PDI": map[string]interface{}{
							"Network Instance": "ctnet",
						},
					},
				},
			},
			expected: []string{"ctnet"},
		},
		{
			name: "multiple Network Instances deduplicated",
			pfcpInfo: map[string]interface{}{
				"ies": map[string]interface{}{
					"Create PDR 1": map[string]interface{}{
						"PDI": map[string]interface{}{
							"Network Instance": "internet",
						},
					},
					"Create PDR 2": map[string]interface{}{
						"PDI": map[string]interface{}{
							"Network Instance": "ctnet",
						},
					},
					"Create PDR 3": map[string]interface{}{
						"PDI": map[string]interface{}{
							"Network Instance": "internet",
						},
					},
				},
			},
			expected: []string{"ctnet", "internet"}, // sorted, deduplicated
		},
		{
			name: "no Network Instance",
			pfcpInfo: map[string]interface{}{
				"ies": map[string]interface{}{
					"F-SEID": map[string]interface{}{
						"SEID": "0x1234",
					},
				},
			},
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPFCPDnnsFromPacket(tc.pfcpInfo)
			if len(got) != len(tc.expected) {
				t.Errorf("extractPFCPDnnsFromPacket() got %v, want %v", got, tc.expected)
				return
			}
			for i, v := range got {
				if v != tc.expected[i] {
					t.Errorf("extractPFCPDnnsFromPacket()[%d] = %q, want %q", i, v, tc.expected[i])
				}
			}
		})
	}
}

// TestIsPFCPSessionMessage tests the session message type checker.
func TestIsPFCPSessionMessage(t *testing.T) {
	tests := []struct {
		msgType  string
		expected bool
	}{
		{"50", true},  // Session Establishment Request
		{"51", true},  // Session Establishment Response
		{"52", true},  // Session Modification Request
		{"53", true},  // Session Modification Response
		{"54", true},  // Session Deletion Request
		{"55", true},  // Session Deletion Response
		{"56", true},  // Session Report Request
		{"57", true},  // Session Report Response
		{"1", false},  // Heartbeat Request
		{"2", false},  // Heartbeat Response
		{"5", false},  // Association Setup Request
		{"6", false},  // Association Setup Response
		{"49", false}, // Just below session range
		{"58", false}, // Just above session range
		{"", false},   // Empty
	}

	for _, tc := range tests {
		got := isPFCPSessionMessage(tc.msgType)
		if got != tc.expected {
			t.Errorf("isPFCPSessionMessage(%q) = %v, want %v", tc.msgType, got, tc.expected)
		}
	}
}

