package nasanalyzer

import "time"

type NASCategory string

const (
	CategoryMM NASCategory = "5gmm"
	CategorySM NASCategory = "5gsm"
)

type NASDirection string

const (
	DirectionUplink   NASDirection = "uplink"
	DirectionDownlink NASDirection = "downlink"
	DirectionUnknown  NASDirection = "unknown"
)

type Message struct {
	ID                 string       `json:"id"`
	FrameNumber        int          `json:"frame_number"`
	Timestamp          time.Time    `json:"timestamp"`
	SourceIP           string       `json:"source_ip"`
	DestinationIP      string       `json:"destination_ip"`
	Direction          NASDirection `json:"direction"`
	Category           NASCategory  `json:"category"`
	MessageTypeCode    string       `json:"message_type_code"`
	MessageType        string       `json:"message_type"`
	SecurityHeaderType string       `json:"security_header_type,omitempty"`
	SecurityHeaderName string       `json:"security_header_name,omitempty"`
	SequenceNumber     string       `json:"sequence_number,omitempty"`
	ProcTransID        string       `json:"procedure_transaction_id,omitempty"`
	PDUSessionID       string       `json:"pdu_session_id,omitempty"`
	AMFUENGAPID        string       `json:"amf_ue_ngap_id,omitempty"`
	RANUENGAPID        string       `json:"ran_ue_ngap_id,omitempty"`
	NGAPProcedureCode  string       `json:"ngap_procedure_code,omitempty"`
	NGAPPDU            string       `json:"ngap_pdu,omitempty"`
	ElementIDs         []string     `json:"element_ids,omitempty"`
	WiresharkFilter    string       `json:"wireshark_filter"`
}

type AnalysisResult struct {
	Filename     string      `json:"filename"`
	AnalyzedAt   time.Time   `json:"analyzed_at"`
	TotalPackets int         `json:"total_packets"`
	Truncated    bool        `json:"truncated,omitempty"`
	MessageLimit int         `json:"message_limit,omitempty"`
	Statistics   Statistics  `json:"statistics"`
	Messages     []*Message  `json:"messages"`
	TypeStats    []TypeCount `json:"type_stats"`
	Flows        []*Flow     `json:"flows"`
}

type Statistics struct {
	TotalMessages int `json:"total_messages"`
	MMMessages    int `json:"mm_messages"`
	SMMessages    int `json:"sm_messages"`
	Uplink        int `json:"uplink"`
	Downlink      int `json:"downlink"`
	Unknown       int `json:"unknown"`
	Protected     int `json:"protected"`
	Plain         int `json:"plain"`

	TotalFlows        int     `json:"total_flows"`
	SuccessfulFlows   int     `json:"successful_flows"`
	FailedFlows       int     `json:"failed_flows"`
	InProgressFlows   int     `json:"in_progress_flows"`
	FlowSuccessRate   float64 `json:"flow_success_rate"`
	RegistrationFlows int     `json:"registration_flows"`
	Authentication    int     `json:"authentication_flows"`
	SecurityMode      int     `json:"security_mode_flows"`
	PDUSession        int     `json:"pdu_session_flows"`
}

type TypeCount struct {
	Category NASCategory `json:"category"`
	Code     string      `json:"code"`
	Name     string      `json:"name"`
	Count    int         `json:"count"`
	Filter   string      `json:"filter"`
}

type FlowType string

const (
	FlowRegistration   FlowType = "registration"
	FlowAuthentication FlowType = "authentication"
	FlowSecurityMode   FlowType = "security_mode"
	FlowPDUSessionEst  FlowType = "pdu_session_establishment"
)

type FlowStatus string

const (
	FlowStatusSuccess    FlowStatus = "success"
	FlowStatusFailed     FlowStatus = "failed"
	FlowStatusInProgress FlowStatus = "in_progress"
)

type Flow struct {
	ID              string     `json:"id"`
	FlowType        FlowType   `json:"flow_type"`
	Status          FlowStatus `json:"status"`
	StartFrame      int        `json:"start_frame"`
	EndFrame        int        `json:"end_frame,omitempty"`
	StartTime       time.Time  `json:"start_time"`
	EndTime         time.Time  `json:"end_time,omitempty"`
	DurationMs      float64    `json:"duration_ms"`
	RequestMessage  string     `json:"request_message"`
	ResultMessage   string     `json:"result_message,omitempty"`
	FailureReason   string     `json:"failure_reason,omitempty"`
	ProcTransID     string     `json:"procedure_transaction_id,omitempty"`
	PDUSessionID    string     `json:"pdu_session_id,omitempty"`
	AMFUENGAPID     string     `json:"amf_ue_ngap_id,omitempty"`
	RANUENGAPID     string     `json:"ran_ue_ngap_id,omitempty"`
	StepCount       int        `json:"step_count"`
	Steps           []FlowStep `json:"steps"`
	WiresharkFilter string     `json:"wireshark_filter"`
}

type FlowStep struct {
	FrameNumber  int          `json:"frame_number"`
	Timestamp    time.Time    `json:"timestamp"`
	Direction    NASDirection `json:"direction"`
	Category     NASCategory  `json:"category"`
	MessageType  string       `json:"message_type"`
	Code         string       `json:"code"`
	ProcTransID  string       `json:"procedure_transaction_id,omitempty"`
	PDUSessionID string       `json:"pdu_session_id,omitempty"`
}

func MMMessageTypeName(code string) string {
	switch normalizeHex(code) {
	case "0x41":
		return "Registration Request"
	case "0x42":
		return "Registration Accept"
	case "0x43":
		return "Registration Complete"
	case "0x44":
		return "Registration Reject"
	case "0x45":
		return "Deregistration Request"
	case "0x46":
		return "Deregistration Accept"
	case "0x4c":
		return "Service Request"
	case "0x4d":
		return "Service Reject"
	case "0x4e":
		return "Service Accept"
	case "0x4f":
		return "Control Plane Service Request"
	case "0x54":
		return "Configuration Update Command"
	case "0x55":
		return "Configuration Update Complete"
	case "0x56":
		return "Authentication Request"
	case "0x57":
		return "Authentication Response"
	case "0x58":
		return "Authentication Reject"
	case "0x59":
		return "Authentication Failure"
	case "0x5a":
		return "Authentication Result"
	case "0x5b":
		return "Identity Request"
	case "0x5c":
		return "Identity Response"
	case "0x5d":
		return "Security Mode Command"
	case "0x5e":
		return "Security Mode Complete"
	case "0x5f":
		return "Security Mode Reject"
	case "0x64":
		return "5GMM Status"
	case "0x67":
		return "UL NAS Transport"
	case "0x68":
		return "DL NAS Transport"
	default:
		return "NAS 5GMM"
	}
}

func SMMessageTypeName(code string) string {
	switch normalizeHex(code) {
	case "0xc1":
		return "PDU Session Establishment Request"
	case "0xc2":
		return "PDU Session Establishment Accept"
	case "0xc3":
		return "PDU Session Establishment Reject"
	case "0xc5":
		return "PDU Session Authentication Command"
	case "0xc6":
		return "PDU Session Authentication Complete"
	case "0xc7":
		return "PDU Session Authentication Result"
	case "0xc9":
		return "PDU Session Modification Request"
	case "0xca":
		return "PDU Session Modification Reject"
	case "0xcb":
		return "PDU Session Modification Command"
	case "0xcc":
		return "PDU Session Modification Complete"
	case "0xd1":
		return "PDU Session Release Request"
	case "0xd2":
		return "PDU Session Release Reject"
	case "0xd3":
		return "PDU Session Release Command"
	case "0xd4":
		return "PDU Session Release Complete"
	case "0xd6":
		return "5GSM Status"
	default:
		return "NAS 5GSM"
	}
}

func SecurityHeaderName(value string) string {
	switch firstToken(value) {
	case "", "0", "0x0":
		return "Plain NAS"
	case "1", "0x1":
		return "Integrity protected"
	case "2", "0x2":
		return "Integrity protected and ciphered"
	case "3", "0x3":
		return "Integrity protected with new 5G NAS security context"
	case "4", "0x4":
		return "Integrity protected and ciphered with new 5G NAS security context"
	default:
		return "Security protected"
	}
}
