package s11analyzer

import "time"

type TransactionStatus string

const (
	StatusSuccess    TransactionStatus = "success"
	StatusFailed     TransactionStatus = "failed"
	StatusNoResponse TransactionStatus = "no_response"
)

type Message struct {
	ID              string    `json:"id"`
	FrameNumber     int       `json:"frame_number"`
	Timestamp       time.Time `json:"timestamp"`
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	MessageTypeCode int       `json:"message_type_code"`
	MessageType     string    `json:"message_type"`
	SequenceNumber  int       `json:"sequence_number"`
	TEID            string    `json:"teid,omitempty"`
	Cause           string    `json:"cause,omitempty"`
	CauseName       string    `json:"cause_name,omitempty"`
	APN             string    `json:"apn,omitempty"`
	FTEIDIPv4       string    `json:"f_teid_ipv4,omitempty"`
	FTEIDIPv6       string    `json:"f_teid_ipv6,omitempty"`
	WiresharkFilter string    `json:"wireshark_filter"`
}

type Transaction struct {
	ID              string            `json:"id"`
	Procedure       string            `json:"procedure"`
	Status          TransactionStatus `json:"status"`
	SequenceNumber  int               `json:"sequence_number"`
	RequestFrame    int               `json:"request_frame"`
	ResponseFrame   int               `json:"response_frame,omitempty"`
	RequestTime     time.Time         `json:"request_time"`
	ResponseTime    time.Time         `json:"response_time,omitempty"`
	ResponseTimeMs  float64           `json:"response_time_ms"`
	RequestType     string            `json:"request_type"`
	ResponseType    string            `json:"response_type,omitempty"`
	Cause           string            `json:"cause,omitempty"`
	CauseName       string            `json:"cause_name,omitempty"`
	SourceIP        string            `json:"source_ip"`
	DestinationIP   string            `json:"destination_ip"`
	RequestTEID     string            `json:"request_teid,omitempty"`
	ResponseTEID    string            `json:"response_teid,omitempty"`
	APN             string            `json:"apn,omitempty"`
	FTEIDIPv4       string            `json:"f_teid_ipv4,omitempty"`
	WiresharkFilter string            `json:"wireshark_filter"`
}

type AnalysisResult struct {
	Filename       string           `json:"filename"`
	AnalyzedAt     time.Time        `json:"analyzed_at"`
	TotalPackets   int              `json:"total_packets"`
	Statistics     Statistics       `json:"statistics"`
	Messages       []*Message       `json:"messages"`
	TypeStats      []TypeCount      `json:"type_stats"`
	Transactions   []*Transaction   `json:"transactions"`
	ProcedureStats []ProcedureCount `json:"procedure_stats"`
}

type Statistics struct {
	TotalMessages     int     `json:"total_messages"`
	Requests          int     `json:"requests"`
	Responses         int     `json:"responses"`
	TotalTransactions int     `json:"total_transactions"`
	Successful        int     `json:"successful"`
	Failed            int     `json:"failed"`
	NoResponse        int     `json:"no_response"`
	SuccessRate       float64 `json:"success_rate"`
	CreateSession     int     `json:"create_session"`
	ModifyBearer      int     `json:"modify_bearer"`
	DeleteSession     int     `json:"delete_session"`
	BearerOperations  int     `json:"bearer_operations"`
	AvgResponseTimeMs float64 `json:"avg_response_time_ms"`
	MaxResponseTimeMs float64 `json:"max_response_time_ms"`
	MinResponseTimeMs float64 `json:"min_response_time_ms"`
}

type TypeCount struct {
	Code  int    `json:"code"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ProcedureCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func MessageTypeName(code int) string {
	switch code {
	case 32:
		return "Create Session Request"
	case 33:
		return "Create Session Response"
	case 34:
		return "Modify Bearer Request"
	case 35:
		return "Modify Bearer Response"
	case 36:
		return "Delete Session Request"
	case 37:
		return "Delete Session Response"
	case 38:
		return "Change Notification Request"
	case 39:
		return "Change Notification Response"
	case 95:
		return "Create Bearer Request"
	case 96:
		return "Create Bearer Response"
	case 97:
		return "Update Bearer Request"
	case 98:
		return "Update Bearer Response"
	case 99:
		return "Delete Bearer Request"
	case 100:
		return "Delete Bearer Response"
	case 101:
		return "Delete PDN Connection Set Request"
	case 102:
		return "Delete PDN Connection Set Response"
	case 160:
		return "Create Forwarding Tunnel Request"
	case 161:
		return "Create Forwarding Tunnel Response"
	case 170:
		return "Release Access Bearers Request"
	case 171:
		return "Release Access Bearers Response"
	case 179:
		return "PGW Restart Notification"
	case 180:
		return "PGW Restart Notification Acknowledge"
	case 211:
		return "Modify Access Bearers Request"
	case 212:
		return "Modify Access Bearers Response"
	default:
		return "GTPv2 Message"
	}
}

func CauseName(cause string) string {
	switch firstToken(cause) {
	case "16":
		return "Request accepted"
	case "17":
		return "Request accepted partially"
	case "64":
		return "Context not found"
	case "65":
		return "Invalid message format"
	case "66":
		return "Version not supported"
	case "72":
		return "System failure"
	case "73":
		return "No resources available"
	case "87":
		return "UE context without TFT"
	default:
		if firstToken(cause) == "" {
			return ""
		}
		return "Cause " + firstToken(cause)
	}
}
