package protocol

import (
	"testing"
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
