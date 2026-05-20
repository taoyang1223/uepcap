package pfcpsession

import "time"

type SessionStatus string

const (
	StatusSuccess    SessionStatus = "success"
	StatusFailed     SessionStatus = "failed"
	StatusNoResponse SessionStatus = "no_response"
	StatusTimeout    SessionStatus = "timeout"
	StatusRetransmit SessionStatus = "retransmit"
)

const CauseRequestAccepted uint8 = 1

type Message struct {
	FrameNumber     int       `json:"frame_number"`
	Timestamp       time.Time `json:"timestamp"`
	SourceIP        string    `json:"source_ip"`
	DestinationIP   string    `json:"destination_ip"`
	SourcePort      uint16    `json:"source_port"`
	DestinationPort uint16    `json:"destination_port"`
	MessageTypeCode uint8     `json:"message_type_code"`
	HeaderSEID      uint64    `json:"header_seid"`
	FSEID           uint64    `json:"fseid,omitempty"`
	FSEIDIPv4       string    `json:"fseid_ipv4,omitempty"`
	FSEIDIPv6       string    `json:"fseid_ipv6,omitempty"`
	SequenceNumber  uint32    `json:"sequence_number"`
	Cause           *uint8    `json:"cause,omitempty"`
}

type Transaction struct {
	ID              string        `json:"id"`
	RequestSEID     uint64        `json:"request_seid"`
	ResponseSEID    uint64        `json:"response_seid"`
	RequestFSEID    uint64        `json:"request_fseid"`
	ResponseFSEID   uint64        `json:"response_fseid"`
	SequenceNumber  uint32        `json:"sequence_number"`
	MessageType     string        `json:"message_type"`
	MessageTypeCode uint8         `json:"message_type_code"`
	Status          SessionStatus `json:"status"`
	Cause           *uint8        `json:"cause,omitempty"`
	CauseName       string        `json:"cause_name,omitempty"`

	SourceIP      string `json:"source_ip"`
	DestinationIP string `json:"destination_ip"`

	RequestTime    time.Time  `json:"request_time"`
	ResponseTime   *time.Time `json:"response_time,omitempty"`
	ResponseTimeMs *float64   `json:"response_time_ms,omitempty"`

	RequestFrame  int  `json:"request_frame"`
	ResponseFrame *int `json:"response_frame,omitempty"`

	RetransmitCount  int   `json:"retransmit_count"`
	RetransmitFrames []int `json:"retransmit_frames,omitempty"`

	WiresharkFilter string `json:"wireshark_filter"`
	SEIDFilter      string `json:"seid_filter,omitempty"`
}

type AnalysisResult struct {
	Filename     string         `json:"filename"`
	AnalyzedAt   time.Time      `json:"analyzed_at"`
	TotalPackets int            `json:"total_packets"`
	Statistics   Statistics     `json:"statistics"`
	Transactions []*Transaction `json:"transactions"`
}

type Statistics struct {
	TotalTransactions int `json:"total_transactions"`
	Success           int `json:"success"`
	Failed            int `json:"failed"`
	NoResponse        int `json:"no_response"`
	Timeout           int `json:"timeout"`
	Retransmit        int `json:"retransmit"`

	Heartbeat          int `json:"heartbeat"`
	AssociationSetup   int `json:"association_setup"`
	AssociationUpdate  int `json:"association_update"`
	AssociationRelease int `json:"association_release"`
	NodeReport         int `json:"node_report"`

	SessionEstablishment int `json:"session_establishment"`
	SessionModification  int `json:"session_modification"`
	SessionDeletion      int `json:"session_deletion"`
	SessionReport        int `json:"session_report"`

	AvgResponseTimeMs float64 `json:"avg_response_time_ms"`
	MaxResponseTimeMs float64 `json:"max_response_time_ms"`
	MinResponseTimeMs float64 `json:"min_response_time_ms"`
}

func MessageTypeName(msgType uint8) string {
	switch msgType {
	case 1:
		return "Heartbeat Request"
	case 2:
		return "Heartbeat Response"
	case 5:
		return "Association Setup Request"
	case 6:
		return "Association Setup Response"
	case 7:
		return "Association Update Request"
	case 8:
		return "Association Update Response"
	case 9:
		return "Association Release Request"
	case 10:
		return "Association Release Response"
	case 12:
		return "Node Report Request"
	case 13:
		return "Node Report Response"
	case 50:
		return "Session Establishment Request"
	case 51:
		return "Session Establishment Response"
	case 52:
		return "Session Modification Request"
	case 53:
		return "Session Modification Response"
	case 54:
		return "Session Deletion Request"
	case 55:
		return "Session Deletion Response"
	case 56:
		return "Session Report Request"
	case 57:
		return "Session Report Response"
	default:
		return "Unknown"
	}
}

func CauseName(cause uint8) string {
	switch cause {
	case 1:
		return "Request accepted"
	case 64:
		return "Request rejected"
	case 65:
		return "Session context not found"
	case 66:
		return "Mandatory IE missing"
	case 67:
		return "Conditional IE missing"
	case 68:
		return "Invalid length"
	case 69:
		return "Mandatory IE incorrect"
	case 70:
		return "Invalid Forwarding Policy"
	case 71:
		return "Invalid F-TEID allocation option"
	case 72:
		return "No established PFCP Association"
	case 73:
		return "Rule creation/modification Failure"
	case 74:
		return "PFCP entity in congestion"
	case 75:
		return "No resources available"
	case 76:
		return "Service not supported"
	case 77:
		return "System failure"
	default:
		return "Unknown cause"
	}
}

func isRequest(msgType uint8) bool {
	switch msgType {
	case 1, 5, 7, 9, 12, 50, 52, 54, 56:
		return true
	default:
		return false
	}
}

func isResponse(msgType uint8) bool {
	switch msgType {
	case 2, 6, 8, 10, 13, 51, 53, 55, 57:
		return true
	default:
		return false
	}
}

func isSessionMessage(msgType uint8) bool {
	return isRequest(msgType) || isResponse(msgType)
}

func messageTypeCategory(msgType uint8) string {
	switch msgType {
	case 1, 2:
		return "Heartbeat"
	case 5, 6:
		return "Association Setup"
	case 7, 8:
		return "Association Update"
	case 9, 10:
		return "Association Release"
	case 12, 13:
		return "Node Report"
	case 50, 51:
		return "Session Establishment"
	case 52, 53:
		return "Session Modification"
	case 54, 55:
		return "Session Deletion"
	case 56, 57:
		return "Session Report"
	default:
		return "Other"
	}
}
