package ngapanalyzer

import "time"

type Direction string

const (
	DirectionGNBToAMF Direction = "gnb_to_amf"
	DirectionAMFToGNB Direction = "amf_to_gnb"
	DirectionUnknown  Direction = "unknown"
)

type PDUType string

const (
	PDUInitiating        PDUType = "initiating"
	PDUSuccessfulOutcome PDUType = "successful_outcome"
	PDUUnsuccessful      PDUType = "unsuccessful_outcome"
	PDUUnknown           PDUType = "unknown"
)

type TransactionStatus string

const (
	TransactionSuccess    TransactionStatus = "success"
	TransactionFailed     TransactionStatus = "failed"
	TransactionInProgress TransactionStatus = "in_progress"
)

type Message struct {
	ID                 string    `json:"id"`
	FrameNumber        int       `json:"frame_number"`
	Timestamp          time.Time `json:"timestamp"`
	SourceIP           string    `json:"source_ip"`
	DestinationIP      string    `json:"destination_ip"`
	Direction          Direction `json:"direction"`
	ProcedureCode      string    `json:"procedure_code"`
	ProcedureName      string    `json:"procedure_name"`
	PDUCode            string    `json:"pdu_code"`
	PDUType            PDUType   `json:"pdu_type"`
	AMFUENGAPID        string    `json:"amf_ue_ngap_id,omitempty"`
	RANUENGAPID        string    `json:"ran_ue_ngap_id,omitempty"`
	HasNAS             bool      `json:"has_nas"`
	GTPTEID            string    `json:"gtp_teid,omitempty"`
	TransactionCapable bool      `json:"transaction_capable"`
	WiresharkFilter    string    `json:"wireshark_filter"`
}

type Transaction struct {
	ID              string            `json:"id"`
	ProcedureCode   string            `json:"procedure_code"`
	ProcedureName   string            `json:"procedure_name"`
	Status          TransactionStatus `json:"status"`
	StartFrame      int               `json:"start_frame"`
	EndFrame        int               `json:"end_frame,omitempty"`
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time,omitempty"`
	DurationMs      float64           `json:"duration_ms"`
	RequestMessage  string            `json:"request_message"`
	ResultMessage   string            `json:"result_message,omitempty"`
	AMFUENGAPID     string            `json:"amf_ue_ngap_id,omitempty"`
	RANUENGAPID     string            `json:"ran_ue_ngap_id,omitempty"`
	StepCount       int               `json:"step_count"`
	Steps           []TransactionStep `json:"steps"`
	WiresharkFilter string            `json:"wireshark_filter"`
}

type TransactionStep struct {
	FrameNumber   int       `json:"frame_number"`
	Timestamp     time.Time `json:"timestamp"`
	Direction     Direction `json:"direction"`
	ProcedureName string    `json:"procedure_name"`
	PDUType       PDUType   `json:"pdu_type"`
}

type AnalysisResult struct {
	Filename       string           `json:"filename"`
	AnalyzedAt     time.Time        `json:"analyzed_at"`
	TotalPackets   int              `json:"total_packets"`
	Statistics     Statistics       `json:"statistics"`
	Messages       []*Message       `json:"messages"`
	ProcedureStats []ProcedureCount `json:"procedure_stats"`
	Transactions   []*Transaction   `json:"transactions"`
}

type Statistics struct {
	TotalMessages              int     `json:"total_messages"`
	Initiating                 int     `json:"initiating"`
	SuccessfulOutcome          int     `json:"successful_outcome"`
	UnsuccessfulOutcome        int     `json:"unsuccessful_outcome"`
	GNBToAMF                   int     `json:"gnb_to_amf"`
	AMFToGNB                   int     `json:"amf_to_gnb"`
	UnknownDirection           int     `json:"unknown_direction"`
	NASTransport               int     `json:"nas_transport"`
	PDUSessionResource         int     `json:"pdu_session_resource"`
	UEContext                  int     `json:"ue_context"`
	TransactionCapableMessages int     `json:"transaction_capable_messages"`
	MessageOnlyMessages        int     `json:"message_only_messages"`
	TotalTransactions          int     `json:"total_transactions"`
	SuccessfulTransactions     int     `json:"successful_transactions"`
	FailedTransactions         int     `json:"failed_transactions"`
	InProgressTransactions     int     `json:"in_progress_transactions"`
	TransactionSuccessRate     float64 `json:"transaction_success_rate"`
}

type ProcedureCount struct {
	Code               string `json:"code"`
	Name               string `json:"name"`
	Count              int    `json:"count"`
	Filter             string `json:"filter"`
	TransactionCapable bool   `json:"transaction_capable"`
}

func ProcedureName(code string) string {
	switch firstToken(code) {
	case "0":
		return "AMF Configuration Update"
	case "4":
		return "Downlink NAS Transport"
	case "9":
		return "Error Indication"
	case "14":
		return "Initial Context Setup"
	case "15":
		return "Initial UE Message"
	case "19":
		return "NAS Non Delivery Indication"
	case "21":
		return "NG Setup"
	case "24":
		return "Paging"
	case "26":
		return "PDU Session Resource Modify"
	case "28":
		return "PDU Session Resource Release"
	case "29":
		return "PDU Session Resource Setup"
	case "30":
		return "PDU Session Resource Notify"
	case "36":
		return "Reroute NAS Request"
	case "40":
		return "UE Context Modification"
	case "41":
		return "UE Context Release"
	case "42":
		return "UE Context Release Request"
	case "44":
		return "UE Radio Capability Info Indication"
	case "46":
		return "Uplink NAS Transport"
	default:
		if firstToken(code) == "" {
			return "NGAP"
		}
		return "Procedure " + firstToken(code)
	}
}

func PDUTypeFromCode(code string) PDUType {
	switch firstToken(code) {
	case "0":
		return PDUInitiating
	case "1":
		return PDUSuccessfulOutcome
	case "2":
		return PDUUnsuccessful
	default:
		return PDUUnknown
	}
}
