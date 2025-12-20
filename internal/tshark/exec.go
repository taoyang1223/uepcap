package tshark

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
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
	return Exec(ctx, "tshark", args...)
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
	return Exec(ctx, "tshark", args...)
}

// TsharkVerbose runs tshark with -V verbose output
func TsharkVerbose(ctx context.Context, pcapFile string, filter string) (*ExecResult, error) {
	args := []string{"-r", pcapFile, "-V"}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	return Exec(ctx, "tshark", args...)
}

// TsharkExport exports filtered packets to a new pcap file
func TsharkExport(ctx context.Context, inputPcap, outputPcap, filter string) error {
	args := []string{"-r", inputPcap, "-w", outputPcap}
	if filter != "" {
		args = append(args, "-Y", filter)
	}
	result, err := Exec(ctx, "tshark", args...)
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
	return Exec(ctx, "tshark", args...)
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
	return Exec(ctx, "tshark", args...)
}
