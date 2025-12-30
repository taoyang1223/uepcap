package tshark

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// DefaultTimeout is the default command timeout
const DefaultTimeout = 30 * time.Second

// ExecResult contains command execution result
type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// CheckInstalled verifies if a command is available in PATH
func CheckInstalled(name string) error {
	_, err := exec.LookPath(name)
	return err
}

// Exec runs a command with context and timeout
func Exec(ctx context.Context, name string, args ...string) (*ExecResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := &ExecResult{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return result, fmt.Errorf("command execution failed: %w", err)
		}
	}

	return result, nil
}

// tsharkCutShortWarningRegex matches the common warning when an input capture is truncated.
// Example:
//
//	tshark: The file "/path/to/file.pcap" appears to have been cut short in the middle of a packet.
var tsharkCutShortWarningRegex = regexp.MustCompile(`(?m)^tshark: The file ".*" appears to have been cut short in the middle of a packet\.\s*$`)

// isOnlyTsharkCutShortWarning returns true if stderr contains only the "cut short" warning (possibly repeated),
// and nothing else. We can safely treat this as non-fatal for most read/export operations because tshark
// still processes all complete packets and only fails on the final truncated one.
func isOnlyTsharkCutShortWarning(stderr string) bool {
	s := strings.TrimSpace(stderr)
	if s == "" {
		return false
	}
	rest := tsharkCutShortWarningRegex.ReplaceAllString(s, "")
	return strings.TrimSpace(rest) == ""
}

// tolerateTsharkCutShortWarning mutates result to downgrade the truncated-capture warning to exit code 0.
func tolerateTsharkCutShortWarning(result *ExecResult) {
	if result == nil || result.ExitCode == 0 {
		return
	}
	if isOnlyTsharkCutShortWarning(result.Stderr) {
		result.ExitCode = 0
	}
}

// ExecWithTimeout runs a command with specified timeout
func ExecWithTimeout(timeout time.Duration, name string, args ...string) (*ExecResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return Exec(ctx, name, args...)
}

// TsharkFields runs tshark with -T fields output
func TsharkFields(ctx context.Context, pcapFile string, filter string, fields []string) (*ExecResult, error) {
	args := []string{"-r", pcapFile, "-T", "fields"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	// 添加 NAS 解密偏好设置
	args = appendNASDecryptPrefs(args, filter, nil)
	result, err := Exec(ctx, "tshark", args...)
	tolerateTsharkCutShortWarning(result)
	return result, err
}

// TsharkJSON runs tshark with JSON output
func TsharkJSON(ctx context.Context, pcapFile string, filter string, protocols string) (*ExecResult, error) {
	args := []string{"-r", pcapFile, "-T", "json"}
	if protocols != "" {
		args = append(args, "-J", protocols)
	}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	// 添加 NAS 解密偏好设置
	args = appendNASDecryptPrefs(args, filter, strings.Fields(protocols))
	result, err := Exec(ctx, "tshark", args...)
	tolerateTsharkCutShortWarning(result)
	return result, err
}

// TsharkVerbose runs tshark with -V verbose output
func TsharkVerbose(ctx context.Context, pcapFile string, filter string) (*ExecResult, error) {
	args := []string{"-r", pcapFile, "-V"}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	// 添加 NAS 解密偏好设置
	args = appendNASDecryptPrefs(args, filter, nil)
	result, err := Exec(ctx, "tshark", args...)
	tolerateTsharkCutShortWarning(result)
	return result, err
}

// TsharkExport exports filtered packets to a new pcap file
func TsharkExport(ctx context.Context, inputPcap, outputPcap, filter string) error {
	args := []string{"-r", inputPcap, "-w", outputPcap}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	// Keep export consistent with other tshark calls (NAS null decipher prefs etc.)
	args = appendNASDecryptPrefs(args, filter, nil)
	result, err := Exec(ctx, "tshark", args...)
	tolerateTsharkCutShortWarning(result)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("tshark export failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

// Mergecap merges multiple pcap files into one
func Mergecap(ctx context.Context, outputPcap string, inputPcaps ...string) error {
	if len(inputPcaps) == 0 {
		return fmt.Errorf("no input files provided")
	}
	args := []string{"-w", outputPcap}
	args = append(args, inputPcaps...)
	result, err := Exec(ctx, "mergecap", args...)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("mergecap failed: %s", strings.TrimSpace(result.Stderr))
	}
	return nil
}

// TsharkList runs tshark to list packets (basic info)
func TsharkList(ctx context.Context, pcapFile string, filter string) (*ExecResult, error) {
	args := []string{"-r", pcapFile}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	result, err := Exec(ctx, "tshark", args...)
	tolerateTsharkCutShortWarning(result)
	return result, err
}

// TsharkCount counts packets matching a filter
func TsharkCount(ctx context.Context, pcapFile string, filter string) (int, error) {
	result, err := TsharkList(ctx, pcapFile, filter)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return 0, nil
	}
	return len(lines), nil
}

// ASN.1 编码的协议列表（NGAP/S1AP 等），这些协议使用 -J 参数会截断深层 IE
var asn1Protocols = map[string]bool{
	"ngap":    true,
	"s1ap":    true,
	"nas-5gs": true, // NAS 嵌套在 NGAP 中，也需要完整输出
	"nas-eps": true, // NAS 嵌套在 S1AP 中
}

// NAS 5G/EPS 解密相关的 tshark 偏好设置
// 这些设置允许 tshark 尝试解码使用空加密(NEA0/EEA0)的 NAS 消息
// 注意: nas-5gs.dissect_plain_nas 在某些 tshark 版本中不存在，已移除
var nas5gsDecryptPrefs = []string{
	"-o", "nas-5gs.null_decipher:TRUE", // 启用 NAS 5G 空加密解码
}

var nasEpsDecryptPrefs = []string{
	"-o", "nas-eps.null_decipher:TRUE", // 启用 NAS EPS 空加密解码
}

// appendNASDecryptPrefs appends NAS decryption preferences based on filter or protocols
func appendNASDecryptPrefs(args []string, filter string, protocols []string) []string {
	// 检查是否需要添加 NAS 5G 解密偏好
	needNas5gs := strings.Contains(filter, "ngap") || strings.Contains(filter, "nas-5gs") || strings.Contains(filter, "nas_5gs")
	needNasEps := strings.Contains(filter, "s1ap") || strings.Contains(filter, "nas-eps") || strings.Contains(filter, "nas_eps")

	// 也检查协议列表
	for _, p := range protocols {
		if p == "ngap" || p == "nas-5gs" {
			needNas5gs = true
		}
		if p == "s1ap" || p == "nas-eps" {
			needNasEps = true
		}
	}

	if needNas5gs {
		args = append(args, nas5gsDecryptPrefs...)
	}
	if needNasEps {
		args = append(args, nasEpsDecryptPrefs...)
	}

	return args
}

// hasASN1Protocol checks if the protocol list contains ASN.1 encoded protocols
func hasASN1Protocol(protocols []string) bool {
	for _, p := range protocols {
		if asn1Protocols[p] {
			return true
		}
	}
	return false
}

// TsharkCompactJSON runs tshark with JSON output, extracting only essential fields
// For ASN.1 protocols (NGAP/S1AP), -J parameter is NOT used to preserve nested IE fields
// For TLV protocols (PFCP/GTPv2), -J parameter is used to limit output size
func TsharkCompactJSON(ctx context.Context, pcapFile string, filter string, protocols []string) (*ExecResult, error) {
	var args []string

	// 检查是否包含 ASN.1 协议
	// ASN.1 协议（NGAP/S1AP）的 IE 使用深层嵌套结构，-J 参数会截断这些字段
	// 所以对于 ASN.1 协议，不使用 -J 参数，让后处理阶段裁剪
	if hasASN1Protocol(protocols) {
		// 不使用 -J 参数，输出完整 JSON
		args = []string{"-r", pcapFile, "-T", "json"}
	} else {
		// TLV 协议（PFCP/GTPv2/GTP）可以使用 -J 参数优化输出大小
		protoList := "frame ip ipv6 udp tcp sctp"
		for _, p := range protocols {
			protoList += " " + p
		}
		args = []string{"-r", pcapFile, "-T", "json", "-J", protoList}
	}

	if filter != "" {
		args = append(args, "-Y", filter)
	}

	// 添加 NAS 解密偏好设置
	args = appendNASDecryptPrefs(args, filter, protocols)
	result, err := Exec(ctx, "tshark", args...)
	tolerateTsharkCutShortWarning(result)
	return result, err
}

// PacketColumns holds wireshark column display values for a packet.
// These are the same values displayed in Wireshark's packet list.
type PacketColumns struct {
	FrameNumber  string `json:"frame_number"`
	TimeRelative string `json:"time_relative"`
	Source       string `json:"source"`
	Destination  string `json:"destination"`
	Protocol     string `json:"protocol"`
	Length       string `json:"length"`
	Info         string `json:"info"`       // Original _ws.col.Info
	InfoClean    string `json:"info_clean"` // Info with SACK prefix removed
}

// sackPrefixRegex matches SCTP SACK acknowledgement prefix in Info field
// Example: "SACK (TSN: 123456) , " or "SACK (TSN: 123456, ...) , "
var sackPrefixRegex = regexp.MustCompile(`^SACK \([^)]*\) , `)

// CleanInfo removes SCTP SACK prefix from the Info string.
// SCTP often bundles acknowledgements with data, making Info noisy.
// Example: "SACK (TSN: 123456) , InitialUEMessage" -> "InitialUEMessage"
func CleanInfo(info string) string {
	return sackPrefixRegex.ReplaceAllString(info, "")
}

// TsharkPacketColumns extracts wireshark column values for all packets matching a filter.
// Returns a map of frame.number -> PacketColumns.
// Fields extracted: frame.number, frame.time_relative, _ws.col.Source, _ws.col.Destination,
//
//	_ws.col.Protocol, frame.len, _ws.col.Info
func TsharkPacketColumns(ctx context.Context, pcapFile string, filter string) (map[string]*PacketColumns, error) {
	fields := []string{
		"frame.number",
		"frame.time_relative",
		"_ws.col.Source",
		"_ws.col.Destination",
		"_ws.col.Protocol",
		"frame.len",
		"_ws.col.Info",
	}

	args := []string{"-r", pcapFile, "-T", "fields", "-E", "separator=\t"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	if filter != "" {
		args = append(args, "-Y", filter)
	}

	// Add NAS decryption preferences based on filter
	args = appendNASDecryptPrefs(args, filter, nil)

	result, err := Exec(ctx, "tshark", args...)
	tolerateTsharkCutShortWarning(result)
	if err != nil {
		return nil, fmt.Errorf("tshark packet columns failed: %w", err)
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("tshark packet columns failed with exit code %d: %s", result.ExitCode, result.Stderr)
	}

	columns := make(map[string]*PacketColumns)
	lines := strings.Split(strings.TrimSpace(result.Stdout), "\n")

	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 7 {
			// Skip malformed lines
			continue
		}

		frameNum := parts[0]
		info := parts[6]
		columns[frameNum] = &PacketColumns{
			FrameNumber:  frameNum,
			TimeRelative: parts[1],
			Source:       parts[2],
			Destination:  parts[3],
			Protocol:     parts[4],
			Length:       parts[5],
			Info:         info,
			InfoClean:    CleanInfo(info),
		}
	}

	return columns, nil
}
