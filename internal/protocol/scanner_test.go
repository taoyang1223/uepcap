package protocol

import (
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
