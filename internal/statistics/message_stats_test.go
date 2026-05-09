package statistics

import (
	"strings"
	"testing"
)

func TestCountFieldRowsAppliesNASMMElemCorrection(t *testing.T) {
	output := strings.Join([]string{
		fieldLine("0x4c", "", "0x71", "15", "0", "", ""),
		fieldLine("0x4c", "", "", "15", "0", "", ""),
		fieldLine("", "0xc1", "", "", "", "32", "1"),
		fieldLine("", "", "", "", "", "", "50"),
	}, "\n")

	result := countFieldRows(output)

	serviceRequest := findItem(t, result, "nas", "service-request")
	if serviceRequest.RawCount != 2 {
		t.Fatalf("service request raw count = %d, want 2", serviceRequest.RawCount)
	}
	if serviceRequest.Correction != -1 {
		t.Fatalf("service request correction = %d, want -1", serviceRequest.Correction)
	}
	if serviceRequest.Count != 1 {
		t.Fatalf("service request final count = %d, want 1", serviceRequest.Count)
	}
	if serviceRequest.CorrectionReason == "" {
		t.Fatal("service request correction reason is empty")
	}

	initialUE := findItem(t, result, "ngap", "initial-ue-message")
	if initialUE.Count != 2 {
		t.Fatalf("initial ue count = %d, want 2", initialUE.Count)
	}

	smRequest := findItem(t, result, "sm-nas", "pdu-session-establishment-request")
	if smRequest.Count != 1 {
		t.Fatalf("sm request count = %d, want 1", smRequest.Count)
	}

	createSession := findItem(t, result, "s11", "create-session-request")
	if createSession.Count != 1 {
		t.Fatalf("create session count = %d, want 1", createSession.Count)
	}

	heartbeat := findItem(t, result, "pfcp", "pfcp-heartbeat-request")
	if heartbeat.Count != 1 {
		t.Fatalf("heartbeat count = %d, want 1", heartbeat.Count)
	}

	sessionRequest := findItem(t, result, "pfcp", "pfcp-session-establishment-request")
	if sessionRequest.Count != 1 {
		t.Fatalf("pfcp session establishment request count = %d, want 1", sessionRequest.Count)
	}
}

func TestCountFieldRowsKeepsAllConfiguredModules(t *testing.T) {
	result := countFieldRows("")
	wantKeys := []string{"nas", "ngap", "s11", "sm-nas", "pfcp"}
	if len(result.Modules) != len(wantKeys) {
		t.Fatalf("module count = %d, want %d", len(result.Modules), len(wantKeys))
	}
	for i, want := range wantKeys {
		if result.Modules[i].Key != want {
			t.Fatalf("module[%d] key = %q, want %q", i, result.Modules[i].Key, want)
		}
	}
}

func TestMessageDefinitionsUseTsharkValues(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want messageDefinition
	}{
		{name: "NAS service accept", key: "service-accept", want: messageDefinition{Kind: matchNASMM, Value: "0x4e"}},
		{name: "NAS authentication reject", key: "authentication-reject", want: messageDefinition{Kind: matchNASMM, Value: "0x58"}},
		{name: "NAS authentication failure", key: "authentication-failure", want: messageDefinition{Kind: matchNASMM, Value: "0x59"}},
		{name: "NGAP downlink NAS transport", key: "downlink-nas-transport", want: messageDefinition{Kind: matchNGAP, Value: "4", PDU: "0"}},
		{name: "NGAP uplink NAS transport", key: "uplink-nas-transport", want: messageDefinition{Kind: matchNGAP, Value: "46", PDU: "0"}},
		{name: "NGAP initial context setup request", key: "initial-context-setup-request", want: messageDefinition{Kind: matchNGAP, Value: "14", PDU: "0"}},
		{name: "NGAP UE context release command", key: "ue-context-release-command", want: messageDefinition{Kind: matchNGAP, Value: "41", PDU: "0"}},
		{name: "NGAP UE context release request", key: "ue-context-release-request", want: messageDefinition{Kind: matchNGAP, Value: "42", PDU: "0"}},
		{name: "NGAP PDU session resource setup request", key: "pdu-session-resource-setup-request", want: messageDefinition{Kind: matchNGAP, Value: "29", PDU: "0"}},
		{name: "NGAP error indication", key: "error-indication", want: messageDefinition{Kind: matchNGAP, Value: "9", PDU: "0"}},
		{name: "S11 delete PDN connection set request", key: "delete-pdn-connection-set-request", want: messageDefinition{Kind: matchGTPv2, Value: "101"}},
		{name: "S11 stop paging indication", key: "stop-paging-indication", want: messageDefinition{Kind: matchGTPv2, Value: "73"}},
		{name: "S11 release access bearers request", key: "release-access-bearers-request", want: messageDefinition{Kind: matchGTPv2, Value: "170"}},
		{name: "PFCP session establishment request", key: "pfcp-session-establishment-request", want: messageDefinition{Kind: matchPFCP, Value: "50"}},
		{name: "PFCP session establishment response", key: "pfcp-session-establishment-response", want: messageDefinition{Kind: matchPFCP, Value: "51"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findDefinition(t, tc.key)
			if got.Kind != tc.want.Kind {
				t.Fatalf("kind = %q, want %q", got.Kind, tc.want.Kind)
			}
			if got.Value != tc.want.Value {
				t.Fatalf("value = %q, want %q", got.Value, tc.want.Value)
			}
			if got.PDU != tc.want.PDU {
				t.Fatalf("pdu = %q, want %q", got.PDU, tc.want.PDU)
			}
		})
	}
}

func fieldLine(values ...string) string {
	return strings.Join(values, "\t")
}

func findItem(t *testing.T, result *Result, moduleKey, itemKey string) Item {
	t.Helper()
	for _, module := range result.Modules {
		if module.Key != moduleKey {
			continue
		}
		for _, item := range module.Items {
			if item.Key == itemKey {
				return item
			}
		}
	}
	t.Fatalf("item %s/%s not found", moduleKey, itemKey)
	return Item{}
}

func findDefinition(t *testing.T, itemKey string) messageDefinition {
	t.Helper()
	for _, module := range moduleDefinitions {
		for _, item := range module.Items {
			if item.Key == itemKey {
				return item
			}
		}
	}
	t.Fatalf("definition %s not found", itemKey)
	return messageDefinition{}
}
