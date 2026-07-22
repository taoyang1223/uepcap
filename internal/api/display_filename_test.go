package api

import "testing"

func TestDisplayPcapFilename(t *testing.T) {
	tests := []struct {
		name          string
		originalFiles []string
		fallback      string
		want          string
	}{
		{
			name:     "fallback to merged capture",
			fallback: "/data/tmp/job/merged.pcap",
			want:     "merged.pcap",
		},
		{
			name:          "single original capture",
			originalFiles: []string{"/data/tmp/job/source-a.pcap"},
			fallback:      "/data/tmp/job/merged.pcap",
			want:          "source-a.pcap",
		},
		{
			name:          "multiple original captures",
			originalFiles: []string{"/data/tmp/job/source-a.pcap", "/data/tmp/job/source-b.pcapng"},
			fallback:      "/data/tmp/job/merged.pcap",
			want:          "2 files: source-a.pcap, source-b.pcapng",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := displayPcapFilename(tt.originalFiles, tt.fallback); got != tt.want {
				t.Fatalf("displayPcapFilename() = %q, want %q", got, tt.want)
			}
		})
	}
}
