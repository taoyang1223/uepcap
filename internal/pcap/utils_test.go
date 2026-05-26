package pcap

import "testing"

func TestIsPcapFile(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "capture.pcap", want: true},
		{name: "capture.pcap0", want: true},
		{name: "capture.pcap1", want: true},
		{name: "capture.pcap14", want: true},
		{name: "capture.pcapng", want: true},
		{name: "capture.cap", want: true},
		{name: "capture.PCAP0", want: true},
		{name: "capture.PCAP14", want: true},
		{name: "capture.pcapx", want: false},
		{name: "capture.txt", want: false},
		{name: "capture.pcap0.zip", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPcapFile(tt.name); got != tt.want {
				t.Fatalf("IsPcapFile(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
