package statistics

import (
	"strings"
	"testing"
)

func TestCountFieldRowsCountsNASByAnalyzerCategory(t *testing.T) {
	output := strings.Join([]string{
		fieldLine("0x4c", "", "0x71", "15", "0", "", ""),
		fieldLine("0x4c", "", "", "15", "0", "", ""),
		fieldLine("0x4d", "", "", "", "", "", ""),
		fieldLine("0x67", "0xc1", "", "46", "0", "", ""),
		fieldLine("0x54", "", "", "4", "0", "", ""),
		fieldLine("0x55", "", "", "46", "0", "", ""),
		fieldLine("0x56", "", "", "4", "0", "", ""),
		fieldLine("0x57", "", "", "46", "0", "", ""),
		fieldLine("0x5b", "", "", "4", "0", "", ""),
		fieldLine("0x5c", "", "", "46", "0", "", ""),
		fieldLine("", "", "", "21", "0", "", ""),
		fieldLine("", "", "", "21", "1", "", ""),
		fieldLine("", "", "", "24", "0", "", ""),
		fieldLine("", "", "", "44", "0", "", ""),
		fieldLine("", "0xc1", "", "", "", "32", "1"),
		fieldLine("", "", "", "", "", "", "50"),
		fieldLine("", "", "", "", "", "", "", "12", "0"),
		fieldLine("", "", "", "", "", "", "", "13,9,13", "0,1,0"),
		fieldLine("", "", "", "", "", "", "", "40,40", "0,0"),
	}, "\n")

	result := countFieldRows(output)

	serviceRequest := findItem(t, result, "nas", "service-request")
	if serviceRequest.RawCount != 2 {
		t.Fatalf("service request raw count = %d, want 2", serviceRequest.RawCount)
	}
	if serviceRequest.Correction != 0 {
		t.Fatalf("service request correction = %d, want 0", serviceRequest.Correction)
	}
	if serviceRequest.Count != 2 {
		t.Fatalf("service request final count = %d, want 2", serviceRequest.Count)
	}
	if serviceRequest.CorrectionReason != "" {
		t.Fatalf("service request correction reason = %q, want empty", serviceRequest.CorrectionReason)
	}

	serviceReject := findItem(t, result, "nas", "service-reject")
	if serviceReject.Count != 1 {
		t.Fatalf("service reject count = %d, want 1", serviceReject.Count)
	}

	ulNASTransport := findItem(t, result, "nas", "ul-nas-transport")
	if ulNASTransport.Count != 1 {
		t.Fatalf("ul nas transport count = %d, want 1 when carrying 5GSM", ulNASTransport.Count)
	}

	initialUE := findItem(t, result, "ngap", "initial-ue-message")
	if initialUE.Count != 2 {
		t.Fatalf("initial ue count = %d, want 2", initialUE.Count)
	}

	ngSetupRequest := findItem(t, result, "ngap", "ng-setup-request")
	if ngSetupRequest.Count != 1 {
		t.Fatalf("ng setup request count = %d, want 1", ngSetupRequest.Count)
	}

	ngSetupResponse := findItem(t, result, "ngap", "ng-setup-response")
	if ngSetupResponse.Count != 1 {
		t.Fatalf("ng setup response count = %d, want 1", ngSetupResponse.Count)
	}

	paging := findItem(t, result, "ngap", "paging")
	if paging.Count != 1 {
		t.Fatalf("paging count = %d, want 1", paging.Count)
	}

	ueRadioCapabilityInfo := findItem(t, result, "ngap", "ue-radio-capability-info-indication")
	if ueRadioCapabilityInfo.Count != 1 {
		t.Fatalf("ue radio capability info indication count = %d, want 1", ueRadioCapabilityInfo.Count)
	}

	s1apInitialUE := findItem(t, result, "s1ap", "initial-ue-message")
	if s1apInitialUE.Count != 1 {
		t.Fatalf("s1ap initial ue count = %d, want 1", s1apInitialUE.Count)
	}

	s1apUplinkNAS := findItem(t, result, "s1ap", "uplink-nas-transport")
	if s1apUplinkNAS.Count != 2 {
		t.Fatalf("s1ap uplink nas count = %d, want 2", s1apUplinkNAS.Count)
	}

	s1apInitialContextResponse := findItem(t, result, "s1ap", "initial-context-setup-response")
	if s1apInitialContextResponse.Count != 1 {
		t.Fatalf("s1ap initial context setup response count = %d, want 1", s1apInitialContextResponse.Count)
	}

	s1apInitialContextRequest := findItem(t, result, "s1ap", "initial-context-setup-request")
	if s1apInitialContextRequest.Count != 0 {
		t.Fatalf("s1ap initial context setup request count = %d, want 0", s1apInitialContextRequest.Count)
	}

	s1apENBConfigurationTransfer := findItem(t, result, "s1ap", "enb-configuration-transfer")
	if s1apENBConfigurationTransfer.Count != 2 {
		t.Fatalf("s1ap enb configuration transfer count = %d, want 2", s1apENBConfigurationTransfer.Count)
	}

	smRequest := findItem(t, result, "sm-nas", "pdu-session-establishment-request")
	if smRequest.Count != 2 {
		t.Fatalf("sm request count = %d, want 2", smRequest.Count)
	}

	createSession := findItem(t, result, "s11", "create-session-request")
	if createSession.Count != 1 {
		t.Fatalf("create session count = %d, want 1", createSession.Count)
	}

	authRequest := findItem(t, result, "nas", "authentication-request")
	if authRequest.Count != 1 {
		t.Fatalf("authentication request count = %d, want 1", authRequest.Count)
	}

	authResponse := findItem(t, result, "nas", "authentication-response")
	if authResponse.Count != 1 {
		t.Fatalf("authentication response count = %d, want 1", authResponse.Count)
	}

	identityRequest := findItem(t, result, "nas", "identity-request")
	if identityRequest.Count != 1 {
		t.Fatalf("identity request count = %d, want 1", identityRequest.Count)
	}

	identityResponse := findItem(t, result, "nas", "identity-response")
	if identityResponse.Count != 1 {
		t.Fatalf("identity response count = %d, want 1", identityResponse.Count)
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
	wantKeys := []string{"nas", "ngap", "s1ap", "s11", "sm-nas", "pfcp"}
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
		name   string
		module string
		key    string
		want   messageDefinition
	}{
		{name: "NAS service accept", module: "nas", key: "service-accept", want: messageDefinition{Kind: matchNASMM, Value: "0x4e"}},
		{name: "NAS service reject", module: "nas", key: "service-reject", want: messageDefinition{Kind: matchNASMM, Value: "0x4d"}},
		{name: "NAS configuration update command", module: "nas", key: "configuration-update-command", want: messageDefinition{Kind: matchNASMM, Value: "0x54"}},
		{name: "NAS authentication request", module: "nas", key: "authentication-request", want: messageDefinition{Kind: matchNASMM, Value: "0x56"}},
		{name: "NAS authentication response", module: "nas", key: "authentication-response", want: messageDefinition{Kind: matchNASMM, Value: "0x57"}},
		{name: "NAS authentication reject", module: "nas", key: "authentication-reject", want: messageDefinition{Kind: matchNASMM, Value: "0x58"}},
		{name: "NAS authentication failure", module: "nas", key: "authentication-failure", want: messageDefinition{Kind: matchNASMM, Value: "0x59"}},
		{name: "NAS identity request", module: "nas", key: "identity-request", want: messageDefinition{Kind: matchNASMM, Value: "0x5b"}},
		{name: "NAS identity response", module: "nas", key: "identity-response", want: messageDefinition{Kind: matchNASMM, Value: "0x5c"}},
		{name: "NGAP downlink NAS transport", module: "ngap", key: "downlink-nas-transport", want: messageDefinition{Kind: matchNGAP, Value: "4", PDU: "0"}},
		{name: "NGAP uplink NAS transport", module: "ngap", key: "uplink-nas-transport", want: messageDefinition{Kind: matchNGAP, Value: "46", PDU: "0"}},
		{name: "NGAP initial context setup request", module: "ngap", key: "initial-context-setup-request", want: messageDefinition{Kind: matchNGAP, Value: "14", PDU: "0"}},
		{name: "NGAP NG setup request", module: "ngap", key: "ng-setup-request", want: messageDefinition{Kind: matchNGAP, Value: "21", PDU: "0"}},
		{name: "NGAP NG setup response", module: "ngap", key: "ng-setup-response", want: messageDefinition{Kind: matchNGAP, Value: "21", PDU: "1"}},
		{name: "NGAP paging", module: "ngap", key: "paging", want: messageDefinition{Kind: matchNGAP, Value: "24", PDU: "0"}},
		{name: "NGAP UE context release command", module: "ngap", key: "ue-context-release-command", want: messageDefinition{Kind: matchNGAP, Value: "41", PDU: "0"}},
		{name: "NGAP UE context release request", module: "ngap", key: "ue-context-release-request", want: messageDefinition{Kind: matchNGAP, Value: "42", PDU: "0"}},
		{name: "NGAP UE radio capability info indication", module: "ngap", key: "ue-radio-capability-info-indication", want: messageDefinition{Kind: matchNGAP, Value: "44", PDU: "0"}},
		{name: "NGAP PDU session resource setup request", module: "ngap", key: "pdu-session-resource-setup-request", want: messageDefinition{Kind: matchNGAP, Value: "29", PDU: "0"}},
		{name: "NGAP error indication", module: "ngap", key: "error-indication", want: messageDefinition{Kind: matchNGAP, Value: "9", PDU: "0"}},
		{name: "S1AP initial UE message", module: "s1ap", key: "initial-ue-message", want: messageDefinition{Kind: matchS1AP, Value: "12", PDU: "0"}},
		{name: "S1AP downlink NAS transport", module: "s1ap", key: "downlink-nas-transport", want: messageDefinition{Kind: matchS1AP, Value: "11", PDU: "0"}},
		{name: "S1AP initial context setup request", module: "s1ap", key: "initial-context-setup-request", want: messageDefinition{Kind: matchS1AP, Value: "9", PDU: "0"}},
		{name: "S1AP UE capability info indication", module: "s1ap", key: "ue-capability-info-indication", want: messageDefinition{Kind: matchS1AP, Value: "22", PDU: "0"}},
		{name: "S1AP eNB configuration transfer", module: "s1ap", key: "enb-configuration-transfer", want: messageDefinition{Kind: matchS1AP, Value: "40", PDU: "0"}},
		{name: "S1AP MME configuration transfer", module: "s1ap", key: "mme-configuration-transfer", want: messageDefinition{Kind: matchS1AP, Value: "41", PDU: "0"}},
		{name: "S11 delete PDN connection set request", module: "s11", key: "delete-pdn-connection-set-request", want: messageDefinition{Kind: matchGTPv2, Value: "101"}},
		{name: "S11 create bearer response", module: "s11", key: "create-bearer-response", want: messageDefinition{Kind: matchGTPv2, Value: "96"}},
		{name: "S11 stop paging indication", module: "s11", key: "stop-paging-indication", want: messageDefinition{Kind: matchGTPv2, Value: "73"}},
		{name: "S11 release access bearers request", module: "s11", key: "release-access-bearers-request", want: messageDefinition{Kind: matchGTPv2, Value: "170"}},
		{name: "PFCP session establishment request", module: "pfcp", key: "pfcp-session-establishment-request", want: messageDefinition{Kind: matchPFCP, Value: "50"}},
		{name: "PFCP session establishment response", module: "pfcp", key: "pfcp-session-establishment-response", want: messageDefinition{Kind: matchPFCP, Value: "51"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findDefinition(t, tc.module, tc.key)
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

func findDefinition(t *testing.T, moduleKey, itemKey string) messageDefinition {
	t.Helper()
	for _, module := range moduleDefinitions {
		if module.Key != moduleKey {
			continue
		}
		for _, item := range module.Items {
			if item.Key == itemKey {
				return item
			}
		}
	}
	t.Fatalf("definition %s/%s not found", moduleKey, itemKey)
	return messageDefinition{}
}
