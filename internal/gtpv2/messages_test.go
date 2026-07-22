package gtpv2

import "testing"

func TestNameCoversExpandedMessageTypes(t *testing.T) {
	tests := []struct {
		code int
		want string
	}{
		{3, "Version Not Supported Indication"},
		{40, "Remote UE Report Notification"},
		{128, "Identification Request"},
		{149, "Detach Notification"},
		{162, "Suspend Notification"},
		{164, "Resume Notification"},
		{176, "Downlink Data Notification"},
		{200, "Update PDN Connection Set Request"},
		{231, "MBMS Session Start Request"},
	}

	for _, tc := range tests {
		if got := Name(tc.code); got != tc.want {
			t.Fatalf("Name(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestNameByStringParsesDecimalAndHex(t *testing.T) {
	tests := []struct {
		code string
		want string
	}{
		{"40", "Remote UE Report Notification"},
		{"0x80", "Identification Request"},
		{"176,177", "Downlink Data Notification"},
	}

	for _, tc := range tests {
		got, ok := NameByString(tc.code)
		if !ok {
			t.Fatalf("NameByString(%q) returned !ok", tc.code)
		}
		if got != tc.want {
			t.Fatalf("NameByString(%q) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

func TestReservedMessageTypeFallsBack(t *testing.T) {
	if got := Name(178); got != "GTPv2 Message" {
		t.Fatalf("Name(178) = %q, want fallback", got)
	}
	if _, ok := NameByString("178"); ok {
		t.Fatal("NameByString(178) returned ok for reserved type")
	}
}
