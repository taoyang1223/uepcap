package s1apanalyzer

import "time"

type Direction string

const (
	DirectionENBToMME Direction = "enb_to_mme"
	DirectionMMEToENB Direction = "mme_to_enb"
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
	MMEUES1APID        string    `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID        string    `json:"enb_ue_s1ap_id,omitempty"`
	HasNAS             bool      `json:"has_nas"`
	GTPTEID            string    `json:"gtp_teid,omitempty"`
	ERABID             string    `json:"erab_id,omitempty"`
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
	MMEUES1APID     string            `json:"mme_ue_s1ap_id,omitempty"`
	ENBUES1APID     string            `json:"enb_ue_s1ap_id,omitempty"`
	ERABID          string            `json:"erab_id,omitempty"`
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
	ENBToMME                   int     `json:"enb_to_mme"`
	MMEToENB                   int     `json:"mme_to_enb"`
	UnknownDirection           int     `json:"unknown_direction"`
	NASTransport               int     `json:"nas_transport"`
	ERAB                       int     `json:"erab"`
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
		return "Handover Preparation"
	case "1":
		return "Handover Resource Allocation"
	case "2":
		return "Handover Notification"
	case "3":
		return "Path Switch Request"
	case "4":
		return "Handover Cancel"
	case "5":
		return "E-RAB Setup"
	case "6":
		return "E-RAB Modify"
	case "7":
		return "E-RAB Release"
	case "8":
		return "E-RAB Release Indication"
	case "9":
		return "Initial Context Setup"
	case "10":
		return "Paging"
	case "11":
		return "Downlink NAS Transport"
	case "12":
		return "Initial UE Message"
	case "13":
		return "Uplink NAS Transport"
	case "14":
		return "Reset"
	case "15":
		return "Error Indication"
	case "16":
		return "NAS Non Delivery Indication"
	case "17":
		return "S1 Setup"
	case "18":
		return "UE Context Release Request"
	case "21":
		return "UE Context Modification"
	case "22":
		return "UE Capability Info Indication"
	case "23":
		return "UE Context Release"
	case "29":
		return "eNB Configuration Update"
	case "30":
		return "MME Configuration Update"
	case "36":
		return "Write Replace Warning"
	case "43":
		return "Kill"
	case "50":
		return "E-RAB Modification Indication"
	case "52":
		return "Reroute NAS Request"
	case "53":
		return "UE Context Modification Indication"
	default:
		if firstToken(code) == "" {
			return "S1AP"
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
