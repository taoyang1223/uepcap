package api

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/packet"
	"gitee.com/yangdadayyds/uepcap/internal/protocol"
	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

// ExportRequest represents export request body
type ExportRequest struct {
	IMSIs     []string `json:"imsis"`
	Protocols []string `json:"protocols"` // ngap, pfcp, s1ap, gtpv2, gtpu
}

// ExportPackets handles POST /api/jobs/{id}/export
// This is now an async operation: returns immediately with filter, pcap generation happens in background
func (h *Handler) ExportPackets(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req ExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if len(req.IMSIs) == 0 {
		writeError(w, http.StatusBadRequest, "no IMSIs specified")
		return
	}

	if len(req.Protocols) == 0 {
		// Default to all protocols
		req.Protocols = []string{"ngap", "pfcp", "s1ap", "gtpv2", "gtpu"}
	}

	// Generate cache key
	cacheKey := generateCacheKey(req.IMSIs, req.Protocols)

	jobDir := h.jobMgr.GetJobDir(id)
	exportDir := filepath.Join(jobDir, "exports")
	os.MkdirAll(exportDir, 0755)

	startTime := time.Now()
	log.Printf("[Export] Starting filter resolution for job %s: %d IMSIs, %d protocols", id, len(req.IMSIs), len(req.Protocols))

	// Phase 1: Quickly resolve all filters (this is the fast part)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	type filterResult struct {
		imsi   string
		filter string
		err    error
	}

	filterChan := make(chan filterResult, len(req.IMSIs))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4) // Max 4 concurrent filter resolutions

	for _, imsi := range req.IMSIs {
		wg.Add(1)
		go func(imsi string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resolver := protocol.NewFilterResolver()
			filter, err := resolver.ResolveFilter(ctx, job.MergedPcap, imsi, req.Protocols)
			filterChan <- filterResult{imsi: imsi, filter: filter, err: err}
		}(imsi)
	}

	go func() {
		wg.Wait()
		close(filterChan)
	}()

	// Collect filter results
	var filters []string
	imsiFilters := make(map[string]string) // imsi -> filter
	var firstError error

	for result := range filterChan {
		if result.err != nil && firstError == nil {
			firstError = fmt.Errorf("failed to resolve filter for IMSI %s: %v", result.imsi, result.err)
			continue
		}
		if result.filter != "" {
			filters = append(filters, result.filter)
			imsiFilters[result.imsi] = result.filter
		}
	}

	log.Printf("[Export] Filter resolution completed in %v, found %d valid filters", time.Since(startTime), len(filters))

	// If no filters found, return error
	if len(filters) == 0 {
		if firstError != nil {
			writeError(w, http.StatusInternalServerError, firstError.Error())
		} else {
			writeError(w, http.StatusNotFound, "no packets found for specified IMSIs")
		}
		return
	}

	// Combine all filters into one display filter
	var combinedFilter string
	if len(filters) == 1 {
		combinedFilter = filters[0]
	} else {
		wrappedFilters := make([]string, len(filters))
		for i, f := range filters {
			wrappedFilters[i] = "(" + f + ")"
		}
		combinedFilter = strings.Join(wrappedFilters, " || ")
	}

	// Check cache after filter resolution so cached responses can still show the
	// Wireshark display filter and IMSI count in the UI.
	if cachedPath, ok := h.jobMgr.GetCachedExport(id, cacheKey); ok {
		if _, err := os.Stat(cachedPath); err == nil {
			filename := filepath.Base(cachedPath)
			writeSuccess(w, map[string]interface{}{
				"download_url": fmt.Sprintf("/api/jobs/%s/download/%s", id, filename),
				"filename":     filename,
				"cached":       true,
				"status":       "completed",
				"filter":       combinedFilter,
				"imsi_count":   len(imsiFilters),
			})
			return
		}
	}

	// Create async export task
	task, err := h.jobMgr.CreateExportTask(id, len(imsiFilters), combinedFilter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create export task")
		return
	}

	// Return immediately with filter - user can copy to Wireshark right away
	writeSuccess(w, map[string]interface{}{
		"task_id":    task.ID,
		"status":     "processing",
		"filter":     combinedFilter,
		"imsi_count": len(imsiFilters),
	})

	// Phase 2: Start async pcap export in background
	go h.runAsyncExport(id, task.ID, cacheKey, job.MergedPcap, exportDir, imsiFilters, combinedFilter)
}

// runAsyncExport performs pcap export in background
func (h *Handler) runAsyncExport(jobID, taskID, cacheKey, mergedPcap, exportDir string, imsiFilters map[string]string, combinedFilter string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	startTime := time.Now()
	log.Printf("[Export] Starting async pcap export for task %s: %d IMSIs", taskID, len(imsiFilters))

	h.jobMgr.UpdateExportTaskStatus(jobID, taskID, "processing", nil)

	type exportResult struct {
		imsi       string
		outputFile string
		err        error
	}

	resultChan := make(chan exportResult, len(imsiFilters))
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 4)

	for imsi, filter := range imsiFilters {
		wg.Add(1)
		go func(imsi, filter string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			outputFile := filepath.Join(exportDir, fmt.Sprintf("ue_%s.pcap", imsi))
			if err := tshark.TsharkExport(ctx, mergedPcap, outputFile, filter); err != nil {
				log.Printf("[Export] IMSI %s export error: %v", imsi, err)
				resultChan <- exportResult{imsi: imsi, err: err}
				return
			}
			resultChan <- exportResult{imsi: imsi, outputFile: outputFile}
		}(imsi, filter)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var exportedFiles []string
	var firstError error
	for result := range resultChan {
		if result.err != nil && firstError == nil {
			firstError = result.err
		}
		if result.outputFile != "" {
			exportedFiles = append(exportedFiles, result.outputFile)
		}
	}

	log.Printf("[Export] Async export completed in %v, %d files exported", time.Since(startTime), len(exportedFiles))

	// Handle results
	if len(exportedFiles) == 0 {
		// Preserve the underlying tshark error when available; otherwise keep generic message.
		if firstError != nil {
			h.jobMgr.UpdateExportTaskStatus(jobID, taskID, "error", firstError)
		} else {
			h.jobMgr.UpdateExportTaskStatus(jobID, taskID, "error", fmt.Errorf("no files exported"))
		}
		return
	}

	var finalFile, filename string
	if len(exportedFiles) == 1 {
		finalFile = exportedFiles[0]
		filename = filepath.Base(finalFile)
	} else {
		zipFile := filepath.Join(exportDir, fmt.Sprintf("ue_export_%s.zip", cacheKey[:8]))
		if err := createZip(zipFile, exportedFiles); err != nil {
			h.jobMgr.UpdateExportTaskStatus(jobID, taskID, "error", err)
			return
		}
		finalFile = zipFile
		filename = filepath.Base(zipFile)
	}

	// Cache the export
	h.jobMgr.CacheExport(jobID, cacheKey, finalFile)

	// Mark task as completed
	downloadURL := fmt.Sprintf("/api/jobs/%s/download/%s", jobID, filename)
	h.jobMgr.CompleteExportTask(jobID, taskID, downloadURL, filename, len(exportedFiles))
	log.Printf("[Export] Task %s completed: %s", taskID, downloadURL)

	// Phase 3: Start async JSON text pre-generation for copy functionality
	go h.preGenerateCompactJSON(jobID, mergedPcap, combinedFilter)
}

// preGenerateCompactJSON pre-generates compact JSON text in background for faster copy
func (h *Handler) preGenerateCompactJSON(jobID, mergedPcap, filter string) {
	// 生成缓存key
	cacheKey := generateTextCacheKey(filter)

	// 检查是否已缓存
	if _, ok := h.jobMgr.GetCachedTextExport(jobID, cacheKey); ok {
		log.Printf("[PreGenJSON] Cache already exists for job %s, skipping", jobID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Printf("[PreGenJSON] Starting pre-generation for job %s", jobID)
	startTime := time.Now()

	// 使用 TsharkCompactJSON 限制输出的协议层
	result, err := tshark.TsharkCompactJSON(ctx, mergedPcap, filter, applicationProtocols)
	if err != nil {
		log.Printf("[PreGenJSON] Failed for job %s: %v", jobID, err)
		return
	}

	if result.ExitCode != 0 {
		log.Printf("[PreGenJSON] tshark error for job %s: %s", jobID, strings.TrimSpace(result.Stderr))
		return
	}

	// 简化 JSON 输出
	compactJSON, err := packet.SimplifyPacketsJSON(result.Stdout)
	if err != nil {
		log.Printf("[PreGenJSON] Failed to simplify JSON for job %s: %v", jobID, err)
		compactJSON = result.Stdout
	}

	// 缓存结果
	h.jobMgr.CacheTextExport(jobID, cacheKey, compactJSON)

	log.Printf("[PreGenJSON] Completed for job %s in %v, original: %d bytes, compact: %d bytes",
		jobID, time.Since(startTime), len(result.Stdout), len(compactJSON))
}

// GetExportStatus handles GET /api/jobs/{id}/export/{taskId}/status
func (h *Handler) GetExportStatus(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("id")
	taskID := r.PathValue("taskId")

	task, ok := h.jobMgr.GetExportTask(jobID, taskID)
	if !ok {
		writeError(w, http.StatusNotFound, "export task not found")
		return
	}

	writeSuccess(w, task.GetInfo())
}

// DownloadExport handles GET /api/jobs/{id}/download/{filename}
func (h *Handler) DownloadExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	filename := r.PathValue("filename")

	if _, ok := h.jobMgr.GetJob(id); !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	// Security: prevent path traversal
	if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
		writeError(w, http.StatusBadRequest, "invalid filename")
		return
	}

	jobDir := h.jobMgr.GetJobDir(id)
	filePath := filepath.Join(jobDir, "exports", filename)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	// Set headers for file download
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	if strings.HasSuffix(filename, ".zip") {
		w.Header().Set("Content-Type", "application/zip")
	} else {
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	}

	http.ServeFile(w, r, filePath)
}

func generateCacheKey(imsis, protocols []string) string {
	// Sort for consistent key
	sortedIMSIs := make([]string, len(imsis))
	copy(sortedIMSIs, imsis)
	sort.Strings(sortedIMSIs)

	sortedProtocols := make([]string, len(protocols))
	copy(sortedProtocols, protocols)
	sort.Strings(sortedProtocols)

	data := strings.Join(sortedIMSIs, ",") + "|" + strings.Join(sortedProtocols, ",")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func createZip(zipPath string, files []string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	for _, file := range files {
		if err := addFileToZip(zipWriter, file); err != nil {
			return err
		}
	}

	return nil
}

func addFileToZip(zipWriter *zip.Writer, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	header.Name = filepath.Base(filePath)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}

// truncateFilter truncates a filter string for logging
func truncateFilter(filter string) string {
	if len(filter) > 100 {
		return filter[:100] + "..."
	}
	return filter
}

// ExportPacketsTextRequest represents export text request body
type ExportPacketsTextRequest struct {
	Filter string `json:"filter"`
}

// 支持的应用层协议列表
// NOTE: http2 is included so SBI (HTTP2) packets are preserved end-to-end (export/text/flow).
var applicationProtocols = []string{"ngap", "nas-5gs", "pfcp", "s1ap", "gtpv2", "gtp", "http2"}

// generateTextCacheKey generates cache key for text export based on filter
func generateTextCacheKey(filter string) string {
	hash := sha256.Sum256([]byte(filter))
	return hex.EncodeToString(hash[:])
}

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

// simplifyPacketsJSON simplifies tshark JSON output to extract key information
func simplifyPacketsJSON(rawJSON string) (string, error) {
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
		// 提取 NGAP IE 内容（类似 PFCP 的处理方式）
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
		// PFCP 的 IE 内容在 tshark 的 JSON 中通常以 pfcp.* 字段（以及若干 *_tree 嵌套结构）呈现。
		// 之前这里为了“压缩”只保留了 msg_type/seid，导致 IE 被丢弃，表现为“PFCP IE 缺失”。
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
		// 提取 S1AP IE 内容（类似 PFCP/NGAP 的处理方式）
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

// pfcpHeaderFieldKeys 是 PFCP 头部/通用字段（非 IE），为了避免“ies”里塞进噪音做过滤。
// 注意：不同 tshark/wireshark 版本字段名可能略有差异，所以这里采取“尽量保守的跳过”。
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
	// 过滤掉 flags 相关字段
	if strings.HasPrefix(k, "pfcp.flags") {
		return true
	}
	// 过滤掉 spare 相关字段
	if strings.HasPrefix(k, "pfcp.spare") {
		return true
	}
	// 过滤掉 response 相关字段（这是 tshark 计算的元数据）
	if strings.HasPrefix(k, "pfcp.response") {
		return true
	}
	return false
}

// extractPFCPIEs 从 pfcp layer 里提取 IE 相关字段。
// 策略：保留除头部字段外的所有 pfcp.* 字段，并对嵌套结构做有限深度裁剪，避免输出爆炸。
func extractPFCPIEs(layer map[string]any) map[string]any {
	// 先过滤掉头部字段，剩下的都视为“IE/IE树/IE字段”
	raw := make(map[string]any)
	for k, v := range layer {
		// 采用排除法：只跳过已知的头部/元数据字段，保留所有其他字段
		// tshark 输出的 PFCP IE 名称通常是人类可读的（如 "Create PDR", "F-SEID" 等），
		// 不一定以 "pfcp." 开头，所以不能用前缀来过滤
		if isPFCPHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	// 对嵌套结构裁剪：深度 5 以获取更详细的 PFCP IE 内容
	ies := extractNestedFields(raw, 5)
	if len(ies) == 0 {
		return nil
	}

	// 再保险：避免头部字段从其它路径“漏进来”
	for k := range pfcpHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// ngapHeaderFieldKeys 是 NGAP 头部/通用字段（非 IE），需要过滤掉
var ngapHeaderFieldKeys = map[string]struct{}{
	"ngap.procedureCode": {},
	"ngap.criticality":   {},
	"ngap.value":         {},
}

func isNGAPHeaderFieldKey(k string) bool {
	if _, ok := ngapHeaderFieldKeys[k]; ok {
		return true
	}
	// 过滤掉一些 PER 编码相关的元数据字段
	if strings.HasPrefix(k, "per.") {
		return true
	}
	return false
}

// extractNGAPIEs 从 ngap layer 里提取 IE 相关字段。
// 策略：采用排除法，只排除头部/元数据字段，保留所有其他字段（包括 IE 内容）。
// tshark 输出的 NGAP IE 名称通常是人类可读的（如 "InitialUEMessage", "RAN-UE-NGAP-ID" 等）
// 注意：NGAP 是 ASN.1 编码，IE 字段在非常深的嵌套中（需要 10+ 层）
func extractNGAPIEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		// 只跳过 ngap.NGAP_PDU 值字段（已单独处理 pduType），
		// 但保留 ngap.NGAP_PDU_tree（包含所有 IE 的树结构）
		if k == "ngap.NGAP_PDU" {
			continue
		}
		// 跳过已知的头部/元数据字段
		if isNGAPHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	// 对嵌套结构裁剪：深度 20 以获取完整的 NGAP IE 内容
	// NGAP ASN.1 结构嵌套非常深，设置足够大的深度确保不丢失 IE
	ies := extractNestedFields(raw, 20)
	if len(ies) == 0 {
		return nil
	}

	// 清理头部字段
	for k := range ngapHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// s1apHeaderFieldKeys 是 S1AP 头部/通用字段（非 IE），需要过滤掉
var s1apHeaderFieldKeys = map[string]struct{}{
	"s1ap.procedureCode": {},
	"s1ap.criticality":   {},
	"s1ap.value":         {},
}

func isS1APHeaderFieldKey(k string) bool {
	if _, ok := s1apHeaderFieldKeys[k]; ok {
		return true
	}
	// 过滤掉 PER 编码相关的元数据字段
	if strings.HasPrefix(k, "per.") {
		return true
	}
	return false
}

// extractS1APIEs 从 s1ap layer 里提取 IE 相关字段。
// 策略：采用排除法，只排除头部/元数据字段，保留所有其他字段（包括 IE 内容）。
// 注意：S1AP 是 ASN.1 编码，IE 字段在非常深的嵌套中（需要 10+ 层）
func extractS1APIEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		// 只跳过 s1ap.S1AP_PDU 值字段（已单独处理 pduType），
		// 但保留 s1ap.S1AP_PDU_tree（包含所有 IE 的树结构）
		if k == "s1ap.S1AP_PDU" {
			continue
		}
		// 跳过已知的头部/元数据字段
		if isS1APHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	// 对嵌套结构裁剪：深度 20 以获取完整的 S1AP IE 内容
	// S1AP ASN.1 结构嵌套非常深，与 NGAP 类似
	ies := extractNestedFields(raw, 20)
	if len(ies) == 0 {
		return nil
	}

	// 清理头部字段
	for k := range s1apHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// gtpv2HeaderFieldKeys 是 GTPv2 头部/通用字段（非 IE），需要过滤掉
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
	// 过滤掉 spare 和 response 相关字段
	if strings.HasPrefix(k, "gtpv2.spare") {
		return true
	}
	if strings.HasPrefix(k, "gtpv2.response") {
		return true
	}
	return false
}

// extractGTPv2IEs 从 gtpv2 layer 里提取 IE 相关字段。
// 策略：采用排除法，只排除头部/元数据字段，保留所有其他字段（包括 IE 内容）。
func extractGTPv2IEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		// 跳过已知的头部/元数据字段
		if isGTPv2HeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	// 对嵌套结构裁剪：深度 5 以获取更详细的 GTPv2 IE 内容
	ies := extractNestedFields(raw, 5)
	if len(ies) == 0 {
		return nil
	}

	// 清理头部字段
	for k := range gtpv2HeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// gtpuHeaderFieldKeys 是 GTP-U 头部/通用字段（非 IE），需要过滤掉
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
	// 过滤掉 spare 相关字段
	if strings.HasPrefix(k, "gtp.spare") {
		return true
	}
	// 过滤掉 flags 相关字段
	if strings.HasPrefix(k, "gtp.flags") {
		return true
	}
	return false
}

// extractGTPUIEs 从 gtp (GTP-U) layer 里提取 IE 相关字段。
// 策略：采用排除法，只排除头部/元数据字段，保留所有其他字段（包括扩展头等）。
func extractGTPUIEs(layer map[string]any) map[string]any {
	raw := make(map[string]any)
	for k, v := range layer {
		// 跳过已知的头部/元数据字段
		if isGTPUHeaderFieldKey(k) {
			continue
		}
		raw[k] = v
	}

	// 对嵌套结构裁剪：深度 4 对 GTP-U 足够
	ies := extractNestedFields(raw, 4)
	if len(ies) == 0 {
		return nil
	}

	// 清理头部字段
	for k := range gtpuHeaderFieldKeys {
		delete(ies, k)
	}

	return ies
}

// extractNestedNASInfo recursively extracts NAS-5GS info from nested structures
func extractNestedNASInfo(data map[string]any) map[string]any {
	info := make(map[string]any)

	// 递归搜索所有 nas-5gs 相关字段
	var searchNAS func(m map[string]any)
	searchNAS = func(m map[string]any) {
		for k, v := range m {
			// 如果找到 nas-5gs 层，直接提取关键信息
			if k == "nas-5gs" {
				if nasLayer, ok := v.(map[string]any); ok {
					nasInfo := extractNASLayerInfo(nasLayer)
					for nk, nv := range nasInfo {
						info[nk] = nv
					}
				}
				continue
			}

			// 提取 NAS 消息类型 (tshark 使用 nas-5gs.mm.message_type 格式)
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
			// 提取安全头类型
			if k == "nas-5gs.security_header_type" {
				if s, ok := v.(string); ok {
					info["security_header"] = s
				}
			}
			// 提取加密消息的 MAC 和序列号（security_header=2/4 时）
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
			// 提取 5GMM 消息类型 ID
			if k == "nas-5gs.mm.type_id" {
				if s, ok := v.(string); ok && s != "" {
					info["type_id"] = s
				}
			}
			// 提取 SUPI/SUCI MSIN
			if k == "nas-5gs.mm.suci.msin" {
				if s, ok := v.(string); ok {
					info["msin"] = s
				}
			}
			// 提取 MCC/MNC
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

			// 递归搜索嵌套 map
			if nested, ok := v.(map[string]any); ok {
				searchNAS(nested)
			}
			// 处理数组
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

	// 递归搜索 NAS 层中的关键字段
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

			// 递归搜索
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
			// 对于数组，只保留前几个元素
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

// ExportPacketsText handles POST /api/jobs/{id}/export/text
// Export filtered packets as compact JSON text using tshark
func (h *Handler) ExportPacketsText(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req ExportPacketsTextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Filter == "" {
		writeError(w, http.StatusBadRequest, "filter is required")
		return
	}

	// 生成缓存key
	cacheKey := generateTextCacheKey(req.Filter)

	// 检查缓存
	if cachedText, ok := h.jobMgr.GetCachedTextExport(id, cacheKey); ok {
		log.Printf("[ExportText] Cache hit for job %s, returning cached result (%d bytes)", id, len(cachedText))
		writeSuccess(w, map[string]interface{}{
			"text":   cachedText,
			"cached": true,
		})
		return
	}

	// Use tshark to export as compact JSON
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Printf("[ExportText] Starting compact JSON export for job %s with filter: %s", id, truncateFilter(req.Filter))

	// 使用 TsharkCompactJSON 限制输出的协议层
	result, err := tshark.TsharkCompactJSON(ctx, job.MergedPcap, req.Filter, applicationProtocols)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to export packets: %v", err))
		return
	}

	if result.ExitCode != 0 {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("tshark error: %s", strings.TrimSpace(result.Stderr)))
		return
	}

	// 简化 JSON 输出
	compactJSON, err := packet.SimplifyPacketsJSON(result.Stdout)
	if err != nil {
		log.Printf("[ExportText] Failed to simplify JSON, using raw output: %v", err)
		compactJSON = result.Stdout
	}

	log.Printf("[ExportText] Compact JSON export completed for job %s, original: %d bytes, compact: %d bytes",
		id, len(result.Stdout), len(compactJSON))

	// 缓存结果
	h.jobMgr.CacheTextExport(id, cacheKey, compactJSON)

	writeSuccess(w, map[string]interface{}{
		"text":   compactJSON,
		"cached": false,
	})
}

// DownloadPacketsText handles POST /api/jobs/{id}/export/text/download
// Export filtered packets as compact JSON text file for download
func (h *Handler) DownloadPacketsText(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := h.jobMgr.GetJob(id)
	if !ok {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}

	var req ExportPacketsTextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	if req.Filter == "" {
		writeError(w, http.StatusBadRequest, "filter is required")
		return
	}

	// 生成缓存key
	cacheKey := generateTextCacheKey(req.Filter)

	var compactJSON string

	// 检查缓存
	if cachedText, ok := h.jobMgr.GetCachedTextExport(id, cacheKey); ok {
		log.Printf("[DownloadText] Cache hit for job %s", id)
		compactJSON = cachedText
	} else {
		// Use tshark to export as compact JSON
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		log.Printf("[DownloadText] Starting compact JSON export for job %s", id)

		result, err := tshark.TsharkCompactJSON(ctx, job.MergedPcap, req.Filter, applicationProtocols)
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to export packets: %v", err))
			return
		}

		if result.ExitCode != 0 {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("tshark error: %s", strings.TrimSpace(result.Stderr)))
			return
		}

		// 简化 JSON 输出
		compactJSON, err = packet.SimplifyPacketsJSON(result.Stdout)
		if err != nil {
			log.Printf("[DownloadText] Failed to simplify JSON, using raw output: %v", err)
			compactJSON = result.Stdout
		}

		// 缓存结果
		h.jobMgr.CacheTextExport(id, cacheKey, compactJSON)
	}

	// Return as downloadable JSON file
	filename := fmt.Sprintf("packets_export_%s.json", time.Now().Format("20060102_150405"))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Write([]byte(compactJSON))
}
