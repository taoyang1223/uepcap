package gtpv2

import (
	"strconv"
	"strings"
)

type MessageType struct {
	Code int
	Key  string
	Name string
}

var MessageTypes = []MessageType{
	{1, "echo-request", "Echo Request"},
	{2, "echo-response", "Echo Response"},
	{3, "version-not-supported-indication", "Version Not Supported Indication"},
	{32, "create-session-request", "Create Session Request"},
	{33, "create-session-response", "Create Session Response"},
	{34, "modify-bearer-request", "Modify Bearer Request"},
	{35, "modify-bearer-response", "Modify Bearer Response"},
	{36, "delete-session-request", "Delete Session Request"},
	{37, "delete-session-response", "Delete Session Response"},
	{38, "change-notification-request", "Change Notification Request"},
	{39, "change-notification-response", "Change Notification Response"},
	{40, "remote-ue-report-notification", "Remote UE Report Notification"},
	{41, "remote-ue-report-acknowledge", "Remote UE Report Acknowledge"},
	{64, "modify-bearer-command", "Modify Bearer Command"},
	{65, "modify-bearer-failure-indication", "Modify Bearer Failure Indication"},
	{66, "delete-bearer-command", "Delete Bearer Command"},
	{67, "delete-bearer-failure-indication", "Delete Bearer Failure Indication"},
	{68, "bearer-resource-command", "Bearer Resource Command"},
	{69, "bearer-resource-failure-indication", "Bearer Resource Failure Indication"},
	{70, "downlink-data-notification-failure-indication", "Downlink Data Notification Failure Indication"},
	{71, "trace-session-activation", "Trace Session Activation"},
	{72, "trace-session-deactivation", "Trace Session Deactivation"},
	{73, "stop-paging-indication", "Stop Paging Indication"},
	{95, "create-bearer-request", "Create Bearer Request"},
	{96, "create-bearer-response", "Create Bearer Response"},
	{97, "update-bearer-request", "Update Bearer Request"},
	{98, "update-bearer-response", "Update Bearer Response"},
	{99, "delete-bearer-request", "Delete Bearer Request"},
	{100, "delete-bearer-response", "Delete Bearer Response"},
	{101, "delete-pdn-connection-set-request", "Delete PDN Connection Set Request"},
	{102, "delete-pdn-connection-set-response", "Delete PDN Connection Set Response"},
	{103, "pgw-downlink-triggering-notification", "PGW Downlink Triggering Notification"},
	{104, "pgw-downlink-triggering-acknowledge", "PGW Downlink Triggering Acknowledge"},
	{128, "identification-request", "Identification Request"},
	{129, "identification-response", "Identification Response"},
	{130, "context-request", "Context Request"},
	{131, "context-response", "Context Response"},
	{132, "context-acknowledge", "Context Acknowledge"},
	{133, "forward-relocation-request", "Forward Relocation Request"},
	{134, "forward-relocation-response", "Forward Relocation Response"},
	{135, "forward-relocation-complete-notification", "Forward Relocation Complete Notification"},
	{136, "forward-relocation-complete-acknowledge", "Forward Relocation Complete Acknowledge"},
	{137, "forward-access-context-notification", "Forward Access Context Notification"},
	{138, "forward-access-context-acknowledge", "Forward Access Context Acknowledge"},
	{139, "relocation-cancel-request", "Relocation Cancel Request"},
	{140, "relocation-cancel-response", "Relocation Cancel Response"},
	{141, "configuration-transfer-tunnel", "Configuration Transfer Tunnel"},
	{149, "detach-notification", "Detach Notification"},
	{150, "detach-acknowledge", "Detach Acknowledge"},
	{151, "cs-paging-indication", "CS Paging Indication"},
	{152, "ran-information-relay", "RAN Information Relay"},
	{153, "alert-mme-notification", "Alert MME Notification"},
	{154, "alert-mme-acknowledge", "Alert MME Acknowledge"},
	{155, "ue-activity-notification", "UE Activity Notification"},
	{156, "ue-activity-acknowledge", "UE Activity Acknowledge"},
	{157, "isr-status-indication", "ISR Status Indication"},
	{158, "ue-registration-query-request", "UE Registration Query Request"},
	{159, "ue-registration-query-response", "UE Registration Query Response"},
	{160, "create-forwarding-tunnel-request", "Create Forwarding Tunnel Request"},
	{161, "create-forwarding-tunnel-response", "Create Forwarding Tunnel Response"},
	{162, "suspend-notification", "Suspend Notification"},
	{163, "suspend-acknowledge", "Suspend Acknowledge"},
	{164, "resume-notification", "Resume Notification"},
	{165, "resume-acknowledge", "Resume Acknowledge"},
	{166, "create-indirect-data-forwarding-tunnel-request", "Create Indirect Data Forwarding Tunnel Request"},
	{167, "create-indirect-data-forwarding-tunnel-response", "Create Indirect Data Forwarding Tunnel Response"},
	{168, "delete-indirect-data-forwarding-tunnel-request", "Delete Indirect Data Forwarding Tunnel Request"},
	{169, "delete-indirect-data-forwarding-tunnel-response", "Delete Indirect Data Forwarding Tunnel Response"},
	{170, "release-access-bearers-request", "Release Access Bearers Request"},
	{171, "release-access-bearers-response", "Release Access Bearers Response"},
	{176, "downlink-data-notification", "Downlink Data Notification"},
	{177, "downlink-data-notification-acknowledge", "Downlink Data Notification Acknowledge"},
	{179, "pgw-restart-notification", "PGW Restart Notification"},
	{180, "pgw-restart-notification-acknowledge", "PGW Restart Notification Acknowledge"},
	{200, "update-pdn-connection-set-request", "Update PDN Connection Set Request"},
	{201, "update-pdn-connection-set-response", "Update PDN Connection Set Response"},
	{211, "modify-access-bearers-request", "Modify Access Bearers Request"},
	{212, "modify-access-bearers-response", "Modify Access Bearers Response"},
	{231, "mbms-session-start-request", "MBMS Session Start Request"},
	{232, "mbms-session-start-response", "MBMS Session Start Response"},
	{233, "mbms-session-update-request", "MBMS Session Update Request"},
	{234, "mbms-session-update-response", "MBMS Session Update Response"},
	{235, "mbms-session-stop-request", "MBMS Session Stop Request"},
	{236, "mbms-session-stop-response", "MBMS Session Stop Response"},
}

var namesByCode = buildNamesByCode()

func Name(code int) string {
	if name, ok := namesByCode[code]; ok {
		return name
	}
	return "GTPv2 Message"
}

func NameByString(code string) (string, bool) {
	parsed, ok := ParseMessageType(code)
	if !ok {
		return "", false
	}
	name, ok := namesByCode[parsed]
	return name, ok
}

func StringNameMap() map[string]string {
	out := make(map[string]string, len(MessageTypes))
	for _, msg := range MessageTypes {
		out[strconv.Itoa(msg.Code)] = msg.Name
	}
	return out
}

func ParseMessageType(code string) (int, bool) {
	code = strings.TrimSpace(code)
	code = strings.Trim(code, `"`)
	if code == "" {
		return 0, false
	}
	if idx := strings.IndexAny(code, ",;"); idx >= 0 {
		code = strings.TrimSpace(code[:idx])
	}
	value, err := strconv.ParseInt(code, 0, 32)
	if err != nil {
		return 0, false
	}
	return int(value), true
}

func buildNamesByCode() map[int]string {
	out := make(map[int]string, len(MessageTypes))
	for _, msg := range MessageTypes {
		out[msg.Code] = msg.Name
	}
	return out
}
