package protocol

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

func TestIsValidUEIPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"10.0.0.1", true},         // Private RFC1918
		{"172.16.0.1", true},       // Private RFC1918
		{"192.168.1.1", true},      // Private RFC1918
		{"100.64.0.1", true},       // CGNAT
		{"8.8.8.8", true},          // Public IP
		{"0.0.0.0", false},         // Zero address
		{"127.0.0.1", false},       // Loopback
		{"255.255.255.255", false}, // Broadcast
		{"224.0.0.1", false},       // Multicast
		{"239.255.255.255", false}, // Multicast
		{"256.1.1.1", false},       // Invalid octet
		{"1.2.3", false},           // Missing octet
		{"1.2.3.4.5", false},       // Too many octets
		{"abc.def.ghi.jkl", false}, // Non-numeric
	}

	for _, test := range tests {
		result := isValidUEIPv4(test.input)
		if result != test.expected {
			t.Errorf("isValidUEIPv4(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestIsPrivateIPv4(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"10.0.0.1", true},        // 10.0.0.0/8
		{"10.255.255.255", true},  // 10.0.0.0/8
		{"172.16.0.1", true},      // 172.16.0.0/12
		{"172.31.255.255", true},  // 172.16.0.0/12
		{"172.15.255.255", false}, // Below 172.16
		{"172.32.0.0", false},     // Above 172.31
		{"192.168.0.1", true},     // 192.168.0.0/16
		{"192.168.255.255", true}, // 192.168.0.0/16
		{"192.167.0.1", false},    // Not 192.168
		{"100.64.0.1", true},      // CGNAT 100.64.0.0/10
		{"100.127.255.255", true}, // CGNAT
		{"100.63.255.255", false}, // Below CGNAT
		{"100.128.0.0", false},    // Above CGNAT
		{"8.8.8.8", false},        // Public
		{"1.1.1.1", false},        // Public
	}

	for _, test := range tests {
		result := isPrivateIPv4(test.input)
		if result != test.expected {
			t.Errorf("isPrivateIPv4(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestExtractUEIPv4(t *testing.T) {
	resolver := &UEIPResolver{}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name: "PDU Address with private IP",
			input: `Frame 1:
    PDU Address: 10.45.0.123
    Some other field`,
			expected: "10.45.0.123",
		},
		{
			name: "IPv4 address keyword",
			input: `Frame 1:
    IPv4 address: 192.168.1.100
    Random text`,
			expected: "192.168.1.100",
		},
		{
			name: "Skip Source Address",
			input: `Frame 1:
    Source Address: 10.0.0.1
    PDU Address: 172.16.5.10`,
			expected: "172.16.5.10",
		},
		{
			name: "No UE IP found",
			input: `Frame 1:
    Source Address: 10.0.0.1
    Destination Address: 10.0.0.2`,
			expected: "",
		},
		{
			name: "Prefer private IP with keyword",
			input: `Frame 1:
    Some field: 8.8.8.8
    PDU Address: 10.45.0.50`,
			expected: "10.45.0.50",
		},
		{
			name: "PDN Address",
			input: `Frame 1:
    PDN Address Allocation
    End User Address: 100.64.1.50`,
			expected: "100.64.1.50",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resolver.extractUEIPv4(test.input)
			if result != test.expected {
				t.Errorf("extractUEIPv4() = %q, expected %q", result, test.expected)
			}
		})
	}
}

func TestFindRanIDsBy5GTMSI(t *testing.T) {
	resolver := &NGAPResolver{}

	tests := []struct {
		name       string
		input      string
		fiveGTMSIs []string
		expected   []string
	}{
		{
			name: "Match 5G-TMSI in InitialUEMessage (hex format)",
			input: `Frame 100:
    RAN-UE-NGAP-ID: 48
    5G-S-TMSI
        AMF Set ID: 1
        AMF Pointer: 0
        5G-TMSI: 0x12345678
Frame 101:
    RAN-UE-NGAP-ID: 49
    MSIN: 9000000004`,
			fiveGTMSIs: []string{"0x12345678"},
			expected:   []string{"48"},
		},
		{
			name: "Match 5G-TMSI in InitialUEMessage (decimal format)",
			input: `Frame 200:
    RAN-UE-NGAP-ID: 50
    5G-TMSI: 305419896
Frame 201:
    RAN-UE-NGAP-ID: 51
    MSIN: 9000000005`,
			fiveGTMSIs: []string{"305419896"},
			expected:   []string{"50"},
		},
		{
			name: "Multiple registrations with same 5G-TMSI",
			input: `Frame 300:
    RAN-UE-NGAP-ID: 60
    5G-TMSI: 0xAABBCCDD
Frame 301:
    RAN-UE-NGAP-ID: 61
    5G-TMSI: 0xAABBCCDD
Frame 302:
    RAN-UE-NGAP-ID: 62
    MSIN: 9000000006`,
			fiveGTMSIs: []string{"0xAABBCCDD"},
			expected:   []string{"60", "61"},
		},
		{
			name: "No matching 5G-TMSI",
			input: `Frame 400:
    RAN-UE-NGAP-ID: 70
    5G-TMSI: 0x99999999
Frame 401:
    RAN-UE-NGAP-ID: 71
    MSIN: 9000000007`,
			fiveGTMSIs: []string{"0x12345678"},
			expected:   []string{},
		},
		{
			name: "Match case-insensitive hex",
			input: `Frame 500:
    RAN-UE-NGAP-ID: 80
    5G-TMSI: 0xabcdef12`,
			fiveGTMSIs: []string{"0xABCDEF12"},
			expected:   []string{"80"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resolver.findRanIDsBy5GTMSI(test.input, test.fiveGTMSIs)

			// Sort for comparison
			sort.Strings(result)
			sort.Strings(test.expected)

			if len(result) != len(test.expected) {
				t.Errorf("findRanIDsBy5GTMSI() returned %d items, expected %d. Got: %v, Expected: %v",
					len(result), len(test.expected), result, test.expected)
				return
			}

			for i := range result {
				if result[i] != test.expected[i] {
					t.Errorf("findRanIDsBy5GTMSI() = %v, expected %v", result, test.expected)
					break
				}
			}
		})
	}
}

func TestExtractRanIDsFromInitialUE(t *testing.T) {
	resolver := &NGAPResolver{}

	tests := []struct {
		name     string
		input    string
		msin     string
		expected []string
	}{
		{
			name: "Single registration with MSIN",
			input: `Frame 1:
    RAN-UE-NGAP-ID: 100
    MSIN: 9000000001`,
			msin:     "9000000001",
			expected: []string{"100"},
		},
		{
			name: "Multiple registrations same MSIN",
			input: `Frame 1:
    RAN-UE-NGAP-ID: 100
    MSIN: 9000000001
Frame 2:
    RAN-UE-NGAP-ID: 101
    MSIN: 9000000001`,
			msin:     "9000000001",
			expected: []string{"100", "101"},
		},
		{
			name: "Different MSIN - no match",
			input: `Frame 1:
    RAN-UE-NGAP-ID: 100
    MSIN: 9000000002`,
			msin:     "9000000001",
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resolver.extractRanIDsFromInitialUE(test.input, test.msin)

			sort.Strings(result)
			sort.Strings(test.expected)

			if len(result) != len(test.expected) {
				t.Errorf("extractRanIDsFromInitialUE() returned %d items, expected %d. Got: %v",
					len(result), len(test.expected), result)
				return
			}

			for i := range result {
				if result[i] != test.expected[i] {
					t.Errorf("extractRanIDsFromInitialUE() = %v, expected %v", result, test.expected)
					break
				}
			}
		})
	}
}

func TestTeidToNgapBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		ok       bool
	}{
		{
			name:     "Hex format - small value",
			input:    "0x00000001",
			expected: "00:00:00:01",
			ok:       true,
		},
		{
			name:     "Hex format - typical TEID",
			input:    "0x10000b4b",
			expected: "10:00:0b:4b",
			ok:       true,
		},
		{
			name:     "Decimal format - small value",
			input:    "1",
			expected: "00:00:00:01",
			ok:       true,
		},
		{
			name:     "Decimal format - larger value",
			input:    "268438347", // 0x10000b4b in decimal
			expected: "10:00:0b:4b",
			ok:       true,
		},
		{
			name:     "Hex format uppercase X",
			input:    "0X000000BB",
			expected: "00:00:00:bb",
			ok:       true,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
			ok:       false,
		},
		{
			name:     "Invalid hex",
			input:    "0xGGGG",
			expected: "",
			ok:       false,
		},
		{
			name:     "Max 32-bit value",
			input:    "0xFFFFFFFF",
			expected: "ff:ff:ff:ff",
			ok:       true,
		},
		{
			name:     "Zero",
			input:    "0",
			expected: "00:00:00:00",
			ok:       true,
		},
		{
			name:     "Whitespace trimmed",
			input:    "  0x00000002  ",
			expected: "00:00:00:02",
			ok:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, ok := teidToNgapBytes(test.input)
			if ok != test.ok {
				t.Errorf("teidToNgapBytes(%q) ok = %v, expected %v", test.input, ok, test.ok)
				return
			}
			if result != test.expected {
				t.Errorf("teidToNgapBytes(%q) = %q, expected %q", test.input, result, test.expected)
			}
		})
	}
}

func TestExtractTEIDsFromSessionEstResp(t *testing.T) {
	resolver := &PFCPResolver{}

	tests := []struct {
		name     string
		output   string
		smfSEIDs []string
		expected []string
	}{
		{
			name: "Single TEID from matching session",
			output: `Frame 100:
    SEID: 0x11ea750173b89fbe
    F-SEID
        SEID: 0x00008a15b24cc000
    F-TEID
        TEID: 0x10000b4b
        IPv4: 10.18.11.20`,
			smfSEIDs: []string{"0x11ea750173b89fbe"},
			expected: []string{"0x10000b4b"},
		},
		{
			name: "Multiple TEIDs from matching session",
			output: `Frame 100:
    SEID: 0x11ea750173b89fbe
    F-TEID
        TEID: 0x10000b4b
        IPv4: 10.18.11.20
    F-TEID
        TEID: 0x10000b4c
        IPv4: 10.18.11.21`,
			smfSEIDs: []string{"0x11ea750173b89fbe"},
			expected: []string{"0x10000b4b", "0x10000b4c"},
		},
		{
			name: "Non-matching session SEID - no TEIDs",
			output: `Frame 100:
    SEID: 0xAAAAAAAAAAAAAAAA
    F-TEID
        TEID: 0x10000b4b
        IPv4: 10.18.11.20`,
			smfSEIDs: []string{"0x11ea750173b89fbe"},
			expected: []string{},
		},
		{
			name: "Multiple frames - mixed matching",
			output: `Frame 100:
    SEID: 0x11ea750173b89fbe
    F-TEID
        TEID: 0x10000b4b
Frame 101:
    SEID: 0xBBBBBBBBBBBBBBBB
    F-TEID
        TEID: 0x20000000
Frame 102:
    SEID: 0x22222222222222
    F-TEID
        TEID: 0x30000000`,
			smfSEIDs: []string{"0x11ea750173b89fbe", "0x22222222222222"},
			expected: []string{"0x10000b4b", "0x30000000"},
		},
		{
			name: "Skip zero TEID",
			output: `Frame 100:
    SEID: 0x11ea750173b89fbe
    F-TEID
        TEID: 0x00000000
    F-TEID
        TEID: 0x10000b4b`,
			smfSEIDs: []string{"0x11ea750173b89fbe"},
			expected: []string{"0x10000b4b"},
		},
		{
			name: "Decimal TEID format",
			output: `Frame 100:
    SEID: 0x11ea750173b89fbe
    F-TEID
        TEID: 268438347`,
			smfSEIDs: []string{"0x11ea750173b89fbe"},
			expected: []string{"268438347"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resolver.extractTEIDsFromSessionEstResp(test.output, test.smfSEIDs)

			sort.Strings(result)
			sort.Strings(test.expected)

			if len(result) != len(test.expected) {
				t.Errorf("extractTEIDsFromSessionEstResp() returned %d items, expected %d. Got: %v, Expected: %v",
					len(result), len(test.expected), result, test.expected)
				return
			}

			for i := range result {
				if result[i] != test.expected[i] {
					t.Errorf("extractTEIDsFromSessionEstResp() = %v, expected %v", result, test.expected)
					break
				}
			}
		})
	}
}

func TestExtractRanIDsFromNGAPVerbose(t *testing.T) {
	resolver := &NGAPResolver{}

	tests := []struct {
		name     string
		output   string
		expected []string
	}{
		{
			name: "Single RAN ID",
			output: `Frame 100:
    RAN-UE-NGAP-ID: 774
    procedureCode: 29`,
			expected: []string{"774"},
		},
		{
			name: "Multiple RAN IDs",
			output: `Frame 100:
    RAN-UE-NGAP-ID: 774
    procedureCode: 29
Frame 101:
    RAN-UE-NGAP-ID: 775
    procedureCode: 29`,
			expected: []string{"774", "775"},
		},
		{
			name: "Duplicate RAN IDs - deduped",
			output: `Frame 100:
    RAN-UE-NGAP-ID: 774
Frame 101:
    RAN-UE-NGAP-ID: 774`,
			expected: []string{"774"},
		},
		{
			name: "No RAN IDs",
			output: `Frame 100:
    procedureCode: 29
    Some other field`,
			expected: []string{},
		},
		{
			name: "RAN ID with AMF ID in same frame",
			output: `Frame 100:
    RAN-UE-NGAP-ID: 780
    AMF-UE-NGAP-ID: 6009
    procedureCode: 29`,
			expected: []string{"780"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := resolver.extractRanIDsFromNGAPVerbose(test.output)

			sort.Strings(result)
			sort.Strings(test.expected)

			if len(result) != len(test.expected) {
				t.Errorf("extractRanIDsFromNGAPVerbose() returned %d items, expected %d. Got: %v, Expected: %v",
					len(result), len(test.expected), result, test.expected)
				return
			}

			for i := range result {
				if result[i] != test.expected[i] {
					t.Errorf("extractRanIDsFromNGAPVerbose() = %v, expected %v", result, test.expected)
					break
				}
			}
		})
	}
}

// Integration test using the actual pcap file
// This test is skipped if tshark is not installed or the pcap file doesn't exist
func TestNGAPResolverIntegration(t *testing.T) {
	// Check if tshark is available
	if err := tshark.CheckInstalled("tshark"); err != nil {
		t.Skipf("tshark not installed: %v", err)
	}

	// Check if the test pcap file exists
	pcapFile := "../../过滤之后.pcap"
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skipf("test pcap file not found: %s", pcapFile)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// First scan for IMSIs in the pcap
	scanner := NewIMSIScanner()
	imsis, err := scanner.ScanIMSIs(ctx, pcapFile)
	if err != nil {
		t.Fatalf("ScanIMSIs failed: %v", err)
	}

	if len(imsis) == 0 {
		t.Skip("No IMSIs found in pcap file")
	}

	t.Logf("Found %d IMSIs: %v", len(imsis), imsis)

	// Test NGAP resolution for the first IMSI
	imsi := imsis[0]
	resolver := NewFilterResolver()

	filtersByProto, combinedFilter, err := resolver.ResolveFilters(ctx, pcapFile, imsi, []string{"ngap", "pfcp"})
	if err != nil {
		t.Fatalf("ResolveFilters failed: %v", err)
	}

	t.Logf("IMSI: %s", imsi)
	t.Logf("Filters by protocol: %+v", filtersByProto)
	t.Logf("Combined filter: %s", combinedFilter)

	// Check that NGAP filter is not empty and contains RAN_UE_NGAP_ID
	ngapFilter, ok := filtersByProto["ngap"]
	if !ok || ngapFilter == "" {
		t.Errorf("NGAP filter is empty for IMSI %s", imsi)
	} else {
		// Verify the filter contains expected patterns
		if !strings.Contains(ngapFilter, "ngap.RAN_UE_NGAP_ID") && !strings.Contains(ngapFilter, "ngap.AMF_UE_NGAP_ID") {
			t.Errorf("NGAP filter doesn't contain expected ID patterns: %s", ngapFilter)
		}
		// New requirement: also include nas_5gs.5g_tmsi conditions in NGAP filter
		if !strings.Contains(ngapFilter, "nas_5gs.5g_tmsi") {
			t.Errorf("NGAP filter doesn't contain nas_5gs.5g_tmsi condition: %s", ngapFilter)
		}
		t.Logf("NGAP filter validated: %s", ngapFilter)
	}

	// Check PFCP filter
	pfcpFilter, ok := filtersByProto["pfcp"]
	if !ok || pfcpFilter == "" {
		t.Logf("PFCP filter is empty (may be expected if no PFCP messages for this IMSI)")
	} else {
		t.Logf("PFCP filter: %s", pfcpFilter)
	}
}
