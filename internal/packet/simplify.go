package packet

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CompactPacket represents a simplified packet structure
type CompactPacket struct {
	Frame       CompactFrame   `json:"frame"`
	Layers      CompactLayers  `json:"layers"`
	Application map[string]any `json:"application,omitempty"`
}

// CompactFrame represents frame metadata
type CompactFrame struct {
	Number       string `json:"number"`
	Time         string `json:"time"`          // 相对时间
	TimeAbsolute string `json:"time_absolute"` // 绝对时间 (epoch 秒.纳秒)
	Length       string `json:"len"`
	Protocols    string `json:"protocols"`
}

// CompactLayers represents transport layer info
type CompactLayers struct {
	SrcIP   string `json:"src_ip,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	SrcPort string `json:"src_port,omitempty"`
	DstPort string `json:"dst_port,omitempty"`
	Proto   string `json:"proto,omitempty"` // udp/tcp/sctp
}

// NAS 5GMM 消息类型映射
var nas5GMMMessageTypes = map[string]string{
	"0x41": "Registration request",
	"0x42": "Registration accept",
	"0x43": "Registration complete",
	"0x44": "Registration reject",
	"0x45": "Deregistration request (UE)",
	"0x46": "Deregistration accept (UE)",
	"0x47": "Deregistration request (NW)",
	"0x48": "Deregistration accept (NW)",
	"0x4c": "Service request",
	"0x4d": "Service reject",
	"0x4e": "Service accept",
	"0x54": "Configuration update command",
	"0x55": "Configuration update complete",
	"0x56": "Authentication request",
	"0x57": "Authentication response",
	"0x58": "Authentication reject",
	"0x59": "Authentication failure",
	"0x5a": "Authentication result",
	"0x5b": "Identity request",
	"0x5c": "Identity response",
	"0x5d": "Security mode command",
	"0x5e": "Security mode complete",
	"0x5f": "Security mode reject",
	"0x64": "5GMM status",
	"0x65": "Notification",
	"0x66": "Notification response",
	"0x67": "UL NAS transport",
	"0x68": "DL NAS transport",
}

// NAS 5GSM 消息类型映射
var nas5GSMMessageTypes = map[string]string{
	"0xc1": "PDU session establishment request",
	"0xc2": "PDU session establishment accept",
	"0xc3": "PDU session establishment reject",
	"0xc5": "PDU session authentication command",
	"0xc6": "PDU session authentication complete",
	"0xc9": "PDU session modification request",
	"0xca": "PDU session modification reject",
	"0xcb": "PDU session modification command",
	"0xcc": "PDU session modification complete",
	"0xcd": "PDU session modification command reject",
	"0xd1": "PDU session release request",
	"0xd2": "PDU session release reject",
	"0xd3": "PDU session release command",
	"0xd4": "PDU session release complete",
	"0xd6": "5GSM status",
}

// PFCP 消息类型映射
var pfcpMessageTypes = map[string]string{
	"1":  "Heartbeat Request",
	"2":  "Heartbeat Response",
	"3":  "PFD Management Request",
	"4":  "PFD Management Response",
	"5":  "Association Setup Request",
	"6":  "Association Setup Response",
	"7":  "Association Update Request",
	"8":  "Association Update Response",
	"9":  "Association Release Request",
	"10": "Association Release Response",
	"11": "Version Not Supported Response",
	"12": "Node Report Request",
	"13": "Node Report Response",
	"14": "Session Set Deletion Request",
	"15": "Session Set Deletion Response",
	"50": "Session Establishment Request",
	"51": "Session Establishment Response",
	"52": "Session Modification Request",
	"53": "Session Modification Response",
	"54": "Session Deletion Request",
	"55": "Session Deletion Response",
	"56": "Session Report Request",
	"57": "Session Report Response",
}

// NGAP 过程码映射
var ngapProcedureCodes = map[string]string{
	"0":  "AMFConfigurationUpdate",
	"1":  "AMFStatusIndication",
	"2":  "CellTrafficTrace",
	"3":  "DeactivateTrace",
	"4":  "DownlinkNASTransport",
	"5":  "DownlinkNonUEAssociatedNRPPaTransport",
	"6":  "DownlinkRANConfigurationTransfer",
	"7":  "DownlinkRANStatusTransfer",
	"8":  "DownlinkUEAssociatedNRPPaTransport",
	"9":  "ErrorIndication",
	"10": "HandoverCancel",
	"11": "HandoverNotification",
	"12": "HandoverPreparation",
	"13": "HandoverResourceAllocation",
	"14": "InitialContextSetup",
	"15": "InitialUEMessage",
	"16": "LocationReportingControl",
	"17": "LocationReportingFailureIndication",
	"18": "LocationReport",
	"19": "NASNonDeliveryIndication",
	"20": "NGReset",
	"21": "NGSetup",
	"22": "OverloadStart",
	"23": "OverloadStop",
	"24": "Paging",
	"25": "PathSwitchRequest",
	"26": "PDUSessionResourceModify",
	"27": "PDUSessionResourceModifyIndication",
	"28": "PDUSessionResourceRelease",
	"29": "PDUSessionResourceSetup",
	"30": "PDUSessionResourceNotify",
	"31": "PrivateMessage",
	"32": "PWSCancel",
	"33": "PWSFailureIndication",
	"34": "PWSRestartIndication",
	"35": "RANConfigurationUpdate",
	"36": "RerouteNASRequest",
	"37": "RRCInactiveTransitionReport",
	"38": "TraceFailureIndication",
	"39": "TraceStart",
	"40": "UEContextModification",
	"41": "UEContextRelease",
	"42": "UEContextReleaseRequest",
	"43": "UERadioCapabilityCheck",
	"44": "UERadioCapabilityInfoIndication",
	"45": "UETNLABindingRelease",
	"46": "UplinkNASTransport",
	"47": "UplinkNonUEAssociatedNRPPaTransport",
	"48": "UplinkRANConfigurationTransfer",
	"49": "UplinkRANStatusTransfer",
	"50": "UplinkUEAssociatedNRPPaTransport",
	"51": "WriteReplaceWarning",
	"52": "SecondaryRATDataUsageReport",
}

// GTPv2 消息类型映射
var gtpv2MessageTypes = map[string]string{
	"1":   "Echo Request",
	"2":   "Echo Response",
	"32":  "Create Session Request",
	"33":  "Create Session Response",
	"34":  "Modify Bearer Request",
	"35":  "Modify Bearer Response",
	"36":  "Delete Session Request",
	"37":  "Delete Session Response",
	"38":  "Change Notification Request",
	"39":  "Change Notification Response",
	"64":  "Modify Bearer Command",
	"65":  "Modify Bearer Failure Indication",
	"66":  "Delete Bearer Command",
	"67":  "Delete Bearer Failure Indication",
	"68":  "Bearer Resource Command",
	"69":  "Bearer Resource Failure Indication",
	"70":  "Downlink Data Notification Failure Indication",
	"71":  "Trace Session Activation",
	"72":  "Trace Session Deactivation",
	"73":  "Stop Paging Indication",
	"95":  "Create Bearer Request",
	"96":  "Create Bearer Response",
	"97":  "Update Bearer Request",
	"98":  "Update Bearer Response",
	"99":  "Delete Bearer Request",
	"100": "Delete Bearer Response",
	"162": "Release Access Bearers Request",
	"163": "Release Access Bearers Response",
	"170": "Downlink Data Notification",
	"171": "Downlink Data Notification Ack",
	"176": "Suspend Notification",
	"177": "Suspend Acknowledge",
	"178": "Resume Notification",
	"179": "Resume Acknowledge",
}

// SimplifyPacketsJSON simplifies tshark JSON output to extract key information
func SimplifyPacketsJSON(rawJSON string) (string, error) {
	var packets []map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &packets); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	var compactPackets []CompactPacket
	for _, pkt := range packets {
		compact := extractCompactPacket(pkt)
		if compact != nil {
			compactPackets = append(compactPackets, *compact)
		}
	}

	// 输出简化后的JSON
	result, err := json.MarshalIndent(compactPackets, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal compact JSON: %w", err)
	}

	return string(result), nil
}

// extractCompactPacket extracts key info from a single packet
func extractCompactPacket(pkt map[string]any) *CompactPacket {
	source, ok := pkt["_source"].(map[string]any)
	if !ok {
		return nil
	}

	layers, ok := source["layers"].(map[string]any)
	if !ok {
		return nil
	}

	compact := &CompactPacket{
		Application: make(map[string]any),
	}

	// 提取 frame 信息
	if frame, ok := layers["frame"].(map[string]any); ok {
		compact.Frame = CompactFrame{
			Number:       getStringField(frame, "frame.number"),
			Time:         getStringField(frame, "frame.time_relative"),
			TimeAbsolute: getStringField(frame, "frame.time_epoch"),
			Length:       getStringField(frame, "frame.len"),
			Protocols:    getStringField(frame, "frame.protocols"),
		}
	}

	// 提取 IP 信息
	if ip, ok := layers["ip"].(map[string]any); ok {
		compact.Layers.SrcIP = getStringField(ip, "ip.src")
		compact.Layers.DstIP = getStringField(ip, "ip.dst")
	} else if ipv6, ok := layers["ipv6"].(map[string]any); ok {
		compact.Layers.SrcIP = getStringField(ipv6, "ipv6.src")
		compact.Layers.DstIP = getStringField(ipv6, "ipv6.dst")
	}

	// 提取传输层端口信息
	if udp, ok := layers["udp"].(map[string]any); ok {
		compact.Layers.Proto = "udp"
		compact.Layers.SrcPort = getStringField(udp, "udp.srcport")
		compact.Layers.DstPort = getStringField(udp, "udp.dstport")
	} else if tcp, ok := layers["tcp"].(map[string]any); ok {
		compact.Layers.Proto = "tcp"
		compact.Layers.SrcPort = getStringField(tcp, "tcp.srcport")
		compact.Layers.DstPort = getStringField(tcp, "tcp.dstport")
	} else if sctp, ok := layers["sctp"].(map[string]any); ok {
		compact.Layers.Proto = "sctp"
		compact.Layers.SrcPort = getStringField(sctp, "sctp.srcport")
		compact.Layers.DstPort = getStringField(sctp, "sctp.dstport")
	}

	// 提取应用层协议 (NGAP, NAS-5GS, PFCP, S1AP, GTPv2, GTP)
	appProtocols := []string{"ngap", "nas-5gs", "pfcp", "s1ap", "gtpv2", "gtp"}
	for _, proto := range appProtocols {
		if appLayer, ok := layers[proto].(map[string]any); ok {
			compact.Application[proto] = extractApplicationLayerInfo(proto, appLayer)
		}
	}

	// 如果没有应用层数据，设为nil以省略
	if len(compact.Application) == 0 {
		compact.Application = nil
	}

	return compact
}

// extractApplicationLayerInfo extracts key info from application layer
func extractApplicationLayerInfo(proto string, layer map[string]any) map[string]any {
	info := make(map[string]any)

	switch proto {
	case "ngap":
		// 提取 NGAP 关键信息
		if procCode := getStringField(layer, "ngap.procedureCode"); procCode != "" {
			info["procedureCode"] = procCode
			if name, ok := ngapProcedureCodes[procCode]; ok {
				info["procedure"] = name
			}
		}
		// 提取 NGAP PDU 类型
		for k := range layer {
			if strings.HasPrefix(k, "ngap.") && strings.Contains(k, "PDU") {
				info["pduType"] = strings.TrimPrefix(k, "ngap.")
				break
			}
		}
		// 提取 NGAP IE 内容
		if ies := extractNGAPIEs(layer); len(ies) > 0 {
			info["ies"] = ies
		}
		// 从 NGAP 层中提取嵌套的 NAS 信息
		nasInfo := extractNestedNASInfo(layer)
		if len(nasInfo) > 0 {
			info["nas"] = nasInfo
		}

	case "nas-5gs":
		// 提取 NAS-5GS 消息类型
		if msgType := getStringField(layer, "nas_5gs.mm.message_type"); msgType != "" {
			info["message_type"] = msgType
			if name, ok := nas5GMMMessageTypes[msgType]; ok {
				info["message"] = name
			}
		}
		if msgType := getStringField(layer, "nas_5gs.sm.message_type"); msgType != "" {
			info["sm_message_type"] = msgType
			if name, ok := nas5GSMMessageTypes[msgType]; ok {
				info["sm_message"] = name
			}
		}
		// 提取 IMSI/SUPI
		if supi := getStringField(layer, "nas_5gs.mm.suci.supi"); supi != "" {
			info["supi"] = supi
		}

	case "pfcp":
		// 提取 PFCP 消息类型
		if msgType := getStringField(layer, "pfcp.msg_type"); msgType != "" {
			info["message_type"] = msgType
			if name, ok := pfcpMessageTypes[msgType]; ok {
				info["message"] = name
			}
		}
		if seid := getStringField(layer, "pfcp.seid"); seid != "" {
			info["seid"] = seid
		}
		// PFCP IE 内容
		if ies := extractPFCPIEs(layer); len(ies) > 0 {
			info["ies"] = ies
		}

	case "s1ap":
		// 提取 S1AP 过程码
		if procCode := getStringField(layer, "s1ap.procedureCode"); procCode != "" {
			info["procedureCode"] = procCode
		}
		// 提取 S1AP PDU 类型
		for k := range layer {
			if strings.HasPrefix(k, "s1ap.") && strings.Contains(k, "PDU") {
				info["pduType"] = strings.TrimPrefix(k, "s1ap.")
				break
			}
		}
		// 提取 S1AP IE 内容
		if ies := extractS1APIEs(layer); len(ies) > 0 {
			info["ies"] = ies
		}

	case "gtpv2":
		// 提取 GTPv2 消息类型
		if msgType := getStringField(layer, "gtpv2.message_type"); msgType != "" {
			info["message_type"] = msgType
			if name, ok := gtpv2MessageTypes[msgType]; ok {
				info["message"] = name
			}
		}
		if teid := getStringField(layer, "gtpv2.teid"); teid != "" {
			info["teid"] = teid
		}
		// 提取 GTPv2 IE 内容
		if ies := extractGTPv2IEs(layer); len(ies) > 0 {
			info["ies"] = ies
		}

	case "gtp":
		// 提取 GTP-U 信息
		if msgType := getStringField(layer, "gtp.message"); msgType != "" {
			info["message_type"] = msgType
		}
		if teid := getStringField(layer, "gtp.teid"); teid != "" {
			info["teid"] = teid
		}
		// 提取 GTP-U IE 内容
		if ies := extractGTPUIEs(layer); len(ies) > 0 {
			info["ies"] = ies
		}
	}

	// 如果info为空，返回原始layer的简化版本
	if len(info) == 0 {
		return extractNestedFields(layer, 2)
	}

	return info
}

// pfcpHeaderFieldKeys 是 PFCP 头部/通用字段（非 IE）
var pfcpHeaderFieldKeys = map[string]struct{}{
	"pfcp.version":        {},
	"pfcp.flags":          {},
	"pfcp.flags_tree":     {},
	"pfcp.message_length": {},
	"pfcp.length":         {},
	"pfcp.seqno":          {},
	"pfcp.msg_type":       {},
	"pfcp.seid":           {},
	"pfcp.sp":             {},
	"pfcp.mp":             {},
	"pfcp.spare_oct":      {},
	"pfcp.response_time":  {},
	"pfcp.response_to":    {},
	"pfcp.s":              {},
}

func isPFCPHeaderFieldKey(k string) bool {
	if _, ok := pfcpHeaderFieldKeys[k]; ok {
		return true
	}
	if strings.HasPrefix(k, "pfcp.flags") {
		return true
	}
	if strings.HasPrefix(k, "pfcp.spare") {
		return true
	}
	if strings.HasPrefix(k, "pfcp.response") {
		return true
	}
	return false
}

// extractPFCPIEs 从 pfcp layer 里提取 IE 相关字段
func extractPFCPIEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		if isPFCPHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	ies := extractNestedFields(raw, 5)
	if len(ies) == 0 {
		return nil
	}

	for k := range pfcpHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// ngapHeaderFieldKeys 是 NGAP 头部/通用字段（非 IE）
var ngapHeaderFieldKeys = map[string]struct{}{
	"ngap.procedureCode": {},
	"ngap.criticality":   {},
	"ngap.value":         {},
}

func isNGAPHeaderFieldKey(k string) bool {
	if _, ok := ngapHeaderFieldKeys[k]; ok {
		return true
	}
	if strings.HasPrefix(k, "per.") {
		return true
	}
	return false
}

// extractNGAPIEs 从 ngap layer 里提取 IE 相关字段
func extractNGAPIEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		if k == "ngap.NGAP_PDU" {
			continue
		}
		if isNGAPHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	ies := extractNestedFields(raw, 20)
	if len(ies) == 0 {
		return nil
	}

	for k := range ngapHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// s1apHeaderFieldKeys 是 S1AP 头部/通用字段（非 IE）
var s1apHeaderFieldKeys = map[string]struct{}{
	"s1ap.procedureCode": {},
	"s1ap.criticality":   {},
	"s1ap.value":         {},
}

func isS1APHeaderFieldKey(k string) bool {
	if _, ok := s1apHeaderFieldKeys[k]; ok {
		return true
	}
	if strings.HasPrefix(k, "per.") {
		return true
	}
	return false
}

// extractS1APIEs 从 s1ap layer 里提取 IE 相关字段
func extractS1APIEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		if k == "s1ap.S1AP_PDU" {
			continue
		}
		if isS1APHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	ies := extractNestedFields(raw, 20)
	if len(ies) == 0 {
		return nil
	}

	for k := range s1apHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// gtpv2HeaderFieldKeys 是 GTPv2 头部/通用字段（非 IE）
var gtpv2HeaderFieldKeys = map[string]struct{}{
	"gtpv2.version":        {},
	"gtpv2.flags":          {},
	"gtpv2.message_type":   {},
	"gtpv2.message_length": {},
	"gtpv2.teid":           {},
	"gtpv2.t":              {},
	"gtpv2.p":              {},
	"gtpv2.mp":             {},
	"gtpv2.seqno":          {},
	"gtpv2.spare":          {},
	"gtpv2.spare1":         {},
	"gtpv2.spare2":         {},
	"gtpv2.spare3":         {},
	"gtpv2.response_in":    {},
	"gtpv2.response_to":    {},
	"gtpv2.response_time":  {},
}

func isGTPv2HeaderFieldKey(k string) bool {
	if _, ok := gtpv2HeaderFieldKeys[k]; ok {
		return true
	}
	if strings.HasPrefix(k, "gtpv2.spare") {
		return true
	}
	if strings.HasPrefix(k, "gtpv2.response") {
		return true
	}
	return false
}

// extractGTPv2IEs 从 gtpv2 layer 里提取 IE 相关字段
func extractGTPv2IEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		if isGTPv2HeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	ies := extractNestedFields(raw, 5)
	if len(ies) == 0 {
		return nil
	}

	for k := range gtpv2HeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// gtpuHeaderFieldKeys 是 GTP-U 头部/通用字段（非 IE）
var gtpuHeaderFieldKeys = map[string]struct{}{
	"gtp.version": {},
	"gtp.flags":   {},
	"gtp.message": {},
	"gtp.length":  {},
	"gtp.teid":    {},
	"gtp.npdu":    {},
	"gtp.next":    {},
	"gtp.ext_hdr": {},
	"gtp.spare":   {},
	"gtp.e":       {},
	"gtp.s":       {},
	"gtp.pn":      {},
	"gtp.pt":      {},
}

func isGTPUHeaderFieldKey(k string) bool {
	if _, ok := gtpuHeaderFieldKeys[k]; ok {
		return true
	}
	if strings.HasPrefix(k, "gtp.spare") {
		return true
	}
	if strings.HasPrefix(k, "gtp.flags") {
		return true
	}
	return false
}

// extractGTPUIEs 从 gtp (GTP-U) layer 里提取 IE 相关字段
func extractGTPUIEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		if isGTPUHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	ies := extractNestedFields(raw, 4)
	if len(ies) == 0 {
		return nil
	}

	for k := range gtpuHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// extractNestedNASInfo recursively extracts NAS-5GS info from nested structures
func extractNestedNASInfo(data map[string]any) map[string]any {
	info := make(map[string]any)

	var searchNAS func(m map[string]any)
	searchNAS = func(m map[string]any) {
		for k, v := range m {
			if k == "nas-5gs" {
				if nasLayer, ok := v.(map[string]any); ok {
					nasInfo := extractNASLayerInfo(nasLayer)
					for nk, nv := range nasInfo {
						info[nk] = nv
					}
				}
				continue
			}

			if k == "nas-5gs.mm.message_type" {
				if s, ok := v.(string); ok {
					info["mm_message_type"] = s
					if name, ok := nas5GMMMessageTypes[s]; ok {
						info["mm_message"] = name
					}
				}
			}
			if k == "nas-5gs.sm.message_type" {
				if s, ok := v.(string); ok {
					info["sm_message_type"] = s
					if name, ok := nas5GSMMessageTypes[s]; ok {
						info["sm_message"] = name
					}
				}
			}
			if k == "nas-5gs.security_header_type" {
				if s, ok := v.(string); ok {
					info["security_header"] = s
				}
			}
			if k == "nas-5gs.msg_auth_code" {
				if s, ok := v.(string); ok {
					info["msg_auth_code"] = s
				}
			}
			if k == "nas-5gs.seq_no" {
				if s, ok := v.(string); ok {
					info["seq_no"] = s
				}
			}
			if k == "nas-5gs.mm.type_id" {
				if s, ok := v.(string); ok && s != "" {
					info["type_id"] = s
				}
			}
			if k == "nas-5gs.mm.suci.msin" {
				if s, ok := v.(string); ok {
					info["msin"] = s
				}
			}
			if k == "e212.mcc" {
				if s, ok := v.(string); ok {
					info["mcc"] = s
				}
			}
			if k == "e212.mnc" {
				if s, ok := v.(string); ok {
					info["mnc"] = s
				}
			}

			if nested, ok := v.(map[string]any); ok {
				searchNAS(nested)
			}
			if arr, ok := v.([]any); ok {
				for _, item := range arr {
					if nested, ok := item.(map[string]any); ok {
						searchNAS(nested)
					}
				}
			}
		}
	}

	searchNAS(data)
	return info
}

// extractNASLayerInfo extracts key info from a NAS-5GS layer
func extractNASLayerInfo(nasLayer map[string]any) map[string]any {
	info := make(map[string]any)

	var search func(m map[string]any)
	search = func(m map[string]any) {
		for k, v := range m {
			switch k {
			case "nas-5gs.mm.message_type":
				if s, ok := v.(string); ok {
					info["mm_message_type"] = s
					if name, ok := nas5GMMMessageTypes[s]; ok {
						info["mm_message"] = name
					}
				}
			case "nas-5gs.sm.message_type":
				if s, ok := v.(string); ok {
					info["sm_message_type"] = s
					if name, ok := nas5GSMMessageTypes[s]; ok {
						info["sm_message"] = name
					}
				}
			case "nas-5gs.security_header_type":
				if s, ok := v.(string); ok {
					info["security_header"] = s
				}
			case "nas-5gs.msg_auth_code":
				if s, ok := v.(string); ok {
					info["msg_auth_code"] = s
				}
			case "nas-5gs.seq_no":
				if s, ok := v.(string); ok {
					info["seq_no"] = s
				}
			case "nas-5gs.mm.type_id":
				if s, ok := v.(string); ok {
					info["type_id"] = s
				}
			case "nas-5gs.mm.suci.msin":
				if s, ok := v.(string); ok {
					info["msin"] = s
				}
			case "e212.mcc":
				if s, ok := v.(string); ok {
					info["mcc"] = s
				}
			case "e212.mnc":
				if s, ok := v.(string); ok {
					info["mnc"] = s
				}
			case "nas-5gs.mm.5gs_reg_type":
				if s, ok := v.(string); ok {
					info["reg_type"] = s
				}
			}

			if nested, ok := v.(map[string]any); ok {
				search(nested)
			}
			if arr, ok := v.([]any); ok {
				for _, item := range arr {
					if nested, ok := item.(map[string]any); ok {
						search(nested)
					}
				}
			}
		}
	}

	search(nasLayer)
	return info
}

// extractNestedFields extracts fields up to a certain depth
func extractNestedFields(data map[string]any, depth int) map[string]any {
	if depth <= 0 {
		return nil
	}

	result := make(map[string]any)
	for k, v := range data {
		switch val := v.(type) {
		case string:
			result[k] = val
		case map[string]any:
			if depth > 1 {
				nested := extractNestedFields(val, depth-1)
				if len(nested) > 0 {
					result[k] = nested
				}
			}
		case []any:
			if len(val) > 0 {
				result[k] = val
			}
		default:
			result[k] = v
		}
	}
	return result
}

// getStringField safely extracts a string field from a map
func getStringField(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val
		case []any:
			if len(val) > 0 {
				if s, ok := val[0].(string); ok {
					return s
				}
			}
		}
	}
	return ""
}
