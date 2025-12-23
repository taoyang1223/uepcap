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

	mermaid := buildDeterministicMermaid(inputJSON, "Test Flow", annotations)

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

	mermaid := buildDeterministicMermaid(inputJSON, "Multi AMF Test", annotations)

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
	mermaid := buildDeterministicMermaid(inputJSON, "No Annotations Test", nil)

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
	mermaid := buildDeterministicMermaid("[]", "Empty Test", nil)

	if !strings.Contains(mermaid, "sequenceDiagram") {
		t.Error("Expected sequenceDiagram header even for empty input")
	}
	if !strings.Contains(mermaid, "autonumber") {
		t.Error("Expected autonumber even for empty input")
	}
}

// TestBuildDeterministicMermaid_InvalidJSON tests handling of invalid JSON.
func TestBuildDeterministicMermaid_InvalidJSON(t *testing.T) {
	mermaid := buildDeterministicMermaid("not valid json", "Invalid Test", nil)

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

	mermaid := buildDeterministicMermaid(inputJSON, "Direction Test", annotations)

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

