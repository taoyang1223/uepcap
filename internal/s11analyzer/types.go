package s11analyzer

import (
	"time"

	gtpv2msg "gitee.com/yangdadayyds/uepcap/internal/gtpv2"
)

type TransactionStatus string

const (
	StatusSuccess    TransactionStatus = "success"
	StatusFailed     TransactionStatus = "failed"
	StatusNoResponse TransactionStatus = "no_response"
	StatusTimeout    TransactionStatus = "timeout"
	StatusRetransmit TransactionStatus = "retransmit"
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
	SourceFile      string    `json:"source_file,omitempty"`
}

type Transaction struct {
	ID               string            `json:"id"`
	Procedure        string            `json:"procedure"`
	Status           TransactionStatus `json:"status"`
	SequenceNumber   int               `json:"sequence_number"`
	RequestFrame     int               `json:"request_frame"`
	ResponseFrame    int               `json:"response_frame,omitempty"`
	RequestTime      time.Time         `json:"request_time"`
	ResponseTime     time.Time         `json:"response_time,omitempty"`
	ResponseTimeMs   float64           `json:"response_time_ms"`
	RequestType      string            `json:"request_type"`
	ResponseType     string            `json:"response_type,omitempty"`
	Cause            string            `json:"cause,omitempty"`
	CauseName        string            `json:"cause_name,omitempty"`
	SourceIP         string            `json:"source_ip"`
	DestinationIP    string            `json:"destination_ip"`
	RequestTEID      string            `json:"request_teid,omitempty"`
	ResponseTEID     string            `json:"response_teid,omitempty"`
	APN              string            `json:"apn,omitempty"`
	FTEIDIPv4        string            `json:"f_teid_ipv4,omitempty"`
	RetransmitCount  int               `json:"retransmit_count"`
	RetransmitFrames []int             `json:"retransmit_frames,omitempty"`
	WiresharkFilter  string            `json:"wireshark_filter"`
	SourceFile       string            `json:"source_file,omitempty"`
	ResponseFile     string            `json:"response_file,omitempty"`
}

type AnalysisResult struct {
	Filename       string           `json:"filename"`
	AnalyzedAt     time.Time        `json:"analyzed_at"`
	TotalPackets   int              `json:"total_packets"`
	Truncated      bool             `json:"truncated,omitempty"`
	MessageLimit   int              `json:"message_limit,omitempty"`
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
	Timeout           int     `json:"timeout"`
	Retransmit        int     `json:"retransmit"`
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
	return gtpv2msg.Name(code)
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
