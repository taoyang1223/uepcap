package protocol

import (
	"reflect"
	"testing"
)

func TestIsValidIMSI(t *testing.T) {
	scanner := NewIMSIScanner()

	tests := []struct {
		input    string
		expected bool
	}{
		{"460110000000001", true},   // Valid 15-digit IMSI
		{"46011000000001", true},    // Valid 14-digit IMSI
		{"4601100000000", false},    // Too short (13 digits)
		{"4601100000000001", false}, // Too long (16 digits)
		{"46011000000000a", false},  // Contains letter
		{"00000000000001", false},   // Test IMSI prefix (filtered)
		{"", false},                 // Empty string
	}

	for _, test := range tests {
		result := scanner.isValidIMSI(test.input)
		if result != test.expected {
			t.Errorf("isValidIMSI(%q) = %v, expected %v", test.input, result, test.expected)
		}
	}
}

func TestGetMSIN(t *testing.T) {
	tests := []struct {
		imsi     string
		expected string
	}{
		{"460110000000001", "0000000001"}, // 15-digit: MCC(3)+MNC(2)+MSIN(10)
		{"46011000000001", "000000001"},   // 14-digit
		{"12345", "12345"},                // Short input (returns as-is)
	}

	for _, test := range tests {
		result := getMSIN(test.imsi)
		if result != test.expected {
			t.Errorf("getMSIN(%q) = %q, expected %q", test.imsi, result, test.expected)
		}
	}
}

func TestGetMSINCandidates(t *testing.T) {
	tests := []struct {
		imsi     string
		expected []string
	}{
		{"460119000036099", []string{"9000036099", "000036099"}},
		{"12345", []string{"12345"}},
	}

	for _, test := range tests {
		result := getMSINCandidates(test.imsi)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("getMSINCandidates(%q) = %v, expected %v", test.imsi, result, test.expected)
		}
	}
}

func TestExtractIMSIsFromFieldLineWithSUCIMSIN(t *testing.T) {
	scanner := NewIMSIScanner()
	fields := []string{"e212.imsi", "pfcp.user_id.supi", "e212.mcc", "e212.mnc", "nas_5gs.mm.suci.msin"}

	tests := []struct {
		name     string
		line     string
		expected []string
	}{
		{
			name:     "Reconstruct from NAS-5GS SUCI MSIN",
			line:     "\t\t460\t11\t9000036099",
			expected: []string{"460119000036099"},
		},
		{
			name:     "Pad one-digit MNC from e212 output",
			line:     "\t\t460\t2\t0000000101",
			expected: []string{"460020000000101"},
		},
		{
			name:     "Keep direct IMSI and reconstructed IMSI deduped",
			line:     "460119000036099\t\t460\t11\t9000036099",
			expected: []string{"460119000036099"},
		},
		{
			name:     "Ignore reconstructed fallback when direct IMSI exists",
			line:     "460020000000011\t\t460\t2\t0000000012",
			expected: []string{"460020000000011"},
		},
		{
			name:     "Extract IMSI from PFCP SUPI",
			line:     "\timsi-460119000036099\t\t\t",
			expected: []string{"460119000036099"},
		},
		{
			name:     "Ignore MSIN without MCC and MNC",
			line:     "\t\t\t\t9000036099",
			expected: []string{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := scanner.extractIMSIsFromFieldLine(fields, test.line)
			if !reflect.DeepEqual(result, test.expected) {
				t.Errorf("extractIMSIsFromFieldLine() = %v, expected %v", result, test.expected)
			}
		})
	}
}

func TestExtractIMSIsFromFieldLinesKeepsDistinctSUCIFallback(t *testing.T) {
	scanner := NewIMSIScanner()
	fields := []string{"e212.imsi", "e212.mcc", "e212.mnc", "nas_5gs.mm.suci.msin"}
	lines := []string{
		"\t460\t11\t9000036099",
		"460020000000011\t460\t2\t0000000011",
		"\t460\t2\t0000000012",
	}

	buckets := scanner.extractIMSIsFromFieldLines(fields, lines)
	result := sortedIMSISet(preferredIMSISet(buckets.primary, buckets.fallback))
	expected := []string{"460020000000011", "460020000000012", "460119000036099"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("preferred IMSIs = %v, expected %v", result, expected)
	}
}

func TestPreferredIMSISetSkipsFallbackForPrimaryMSIN(t *testing.T) {
	primary := map[string]bool{
		"460020000000011": true,
	}
	fallback := map[string]bool{
		"460020000000011": true,
		"460990000000011": true,
		"460020000000012": true,
	}

	result := sortedIMSISet(preferredIMSISet(primary, fallback))
	expected := []string{"460020000000011", "460020000000012"}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("preferred IMSIs = %v, expected %v", result, expected)
	}
}
