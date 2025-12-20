package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"uepcap/internal/protocol"
	"uepcap/internal/tshark"
)

// 支持的协议白名单
var allowedProtocols = map[string]bool{
	"ngap":  true,
	"pfcp":  true,
	"s1ap":  true,
	"gtpv2": true,
	"gtpu":  true,
	"ueip":  true,
}

// IMSI 格式校验：14~15 位数字
var imsiPattern = regexp.MustCompile(`^\d{14,15}$`)

type listIMSIsArgs struct {
	PcapFile       string `json:"pcap_file" jsonschema:"PCAP/PCAPNG 文件路径"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"超时时间（秒），默认 300"`
}

type listIMSIsOut struct {
	IMSIs []string `json:"imsis"`
}

type imsiBriefArgs struct {
	PcapFile       string   `json:"pcap_file" jsonschema:"PCAP/PCAPNG 文件路径"`
	IMSI           string   `json:"imsi" jsonschema:"目标 IMSI（14~15 位数字）"`
	Protocols      []string `json:"protocols,omitempty" jsonschema:"协议列表：ngap/pfcp/s1ap/gtpv2/gtpu/ueip；默认全选"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"超时时间（秒），默认 120"`
}

type imsiBriefOut struct {
	IMSI           string            `json:"imsi"`
	PcapFile       string            `json:"pcap_file"`
	Protocols      []string          `json:"protocols"`
	Filters        map[string]string `json:"filters"`
	CombinedFilter string            `json:"combined_filter"`
	UEIPv4         string            `json:"ue_ipv4,omitempty"`
}

func main() {
	var (
		name    = flag.String("name", "uepcap-mcp", "MCP server name")
		version = flag.String("version", "v0.1.0", "MCP server version")
	)
	flag.Parse()

	// 依赖检查：tshark/mergecap
	if err := checkDependencies(); err != nil {
		log.Fatalf("依赖检查失败: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: *name, Version: *version}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "uepcap_list_imsis",
		Description: "从 PCAP/PCAPNG 文件中扫描并返回 IMSI 列表（去重、排序）。",
	}, handleListIMSIs)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "uepcap_imsi_brief",
		Description: "根据 IMSI 解析关联协议的 display filter，并返回简要 JSON（包含 per-protocol filters 与 combined_filter）。",
	}, handleIMSIBrief)

	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("MCP server 运行失败: %v", err)
	}
}

func checkDependencies() error {
	if err := tshark.CheckInstalled("tshark"); err != nil {
		return fmt.Errorf("tshark not found: %w (install wireshark-cli or wireshark)", err)
	}
	if err := tshark.CheckInstalled("mergecap"); err != nil {
		return fmt.Errorf("mergecap not found: %w (install wireshark-cli or wireshark)", err)
	}
	return nil
}

func validatePcapFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("pcap_file 不能为空")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("pcap_file 路径无效: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("pcap_file 不存在或不可访问: %w", err)
	}
	if st.IsDir() {
		return "", fmt.Errorf("pcap_file 不能是目录")
	}
	return abs, nil
}

// validateIMSI 校验 IMSI 格式（14~15 位数字）
func validateIMSI(imsi string) error {
	imsi = strings.TrimSpace(imsi)
	if imsi == "" {
		return fmt.Errorf("imsi 不能为空")
	}
	if !imsiPattern.MatchString(imsi) {
		return fmt.Errorf("imsi 格式无效：必须是 14~15 位数字，当前值: %q", imsi)
	}
	return nil
}

// normalizeProtocols 校验并规范化协议列表（小写化 + 白名单过滤）
// 返回规范化后的协议列表，以及无效协议的错误（如有）
func normalizeProtocols(protocols []string) ([]string, error) {
	if len(protocols) == 0 {
		// 默认全选
		return []string{"ngap", "pfcp", "s1ap", "gtpv2", "gtpu", "ueip"}, nil
	}

	var normalized []string
	var invalid []string
	seen := make(map[string]bool)

	for _, p := range protocols {
		lower := strings.ToLower(strings.TrimSpace(p))
		if lower == "" {
			continue
		}
		if !allowedProtocols[lower] {
			invalid = append(invalid, p)
			continue
		}
		if !seen[lower] {
			seen[lower] = true
			normalized = append(normalized, lower)
		}
	}

	if len(invalid) > 0 {
		return nil, fmt.Errorf("无效的协议: %v，允许的协议: ngap/pfcp/s1ap/gtpv2/gtpu/ueip", invalid)
	}

	if len(normalized) == 0 {
		return nil, fmt.Errorf("未指定有效协议，允许的协议: ngap/pfcp/s1ap/gtpv2/gtpu/ueip")
	}

	return normalized, nil
}

func handleListIMSIs(ctx context.Context, _ *mcp.CallToolRequest, args listIMSIsArgs) (*mcp.CallToolResult, listIMSIsOut, error) {
	pcapFile, err := validatePcapFile(args.PcapFile)
	if err != nil {
		return mcpErrorResult(err), listIMSIsOut{}, nil
	}
	timeout := 300 * time.Second
	if args.TimeoutSeconds > 0 {
		timeout = time.Duration(args.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	scanner := protocol.NewIMSIScanner()
	imsis, err := scanner.ScanIMSIs(ctx, pcapFile)
	if err != nil {
		return mcpErrorResult(err), listIMSIsOut{}, nil
	}

	out := listIMSIsOut{IMSIs: imsis}
	return mcpJSONResult(out), out, nil
}

func handleIMSIBrief(ctx context.Context, _ *mcp.CallToolRequest, args imsiBriefArgs) (*mcp.CallToolResult, imsiBriefOut, error) {
	// 校验 PCAP 文件
	pcapFile, err := validatePcapFile(args.PcapFile)
	if err != nil {
		return mcpErrorResult(err), imsiBriefOut{}, nil
	}

	// 校验 IMSI 格式
	imsi := strings.TrimSpace(args.IMSI)
	if err := validateIMSI(imsi); err != nil {
		return mcpErrorResult(err), imsiBriefOut{}, nil
	}

	// 校验并规范化协议列表
	protocols, err := normalizeProtocols(args.Protocols)
	if err != nil {
		return mcpErrorResult(err), imsiBriefOut{}, nil
	}

	timeout := 120 * time.Second
	if args.TimeoutSeconds > 0 {
		timeout = time.Duration(args.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resolver := protocol.NewFilterResolver()
	filters, combined, err := resolver.ResolveFilters(ctx, pcapFile, imsi, protocols)
	if err != nil {
		return mcpErrorResult(err), imsiBriefOut{}, nil
	}

	out := imsiBriefOut{
		IMSI:           imsi,
		PcapFile:       pcapFile,
		Protocols:      protocols,
		Filters:        filters,
		CombinedFilter: combined,
	}
	if ueipFilter, ok := filters["ueip"]; ok {
		// ueip filter is like: ip.addr == X
		const prefix = "ip.addr == "
		if strings.HasPrefix(ueipFilter, prefix) {
			out.UEIPv4 = strings.TrimSpace(strings.TrimPrefix(ueipFilter, prefix))
		}
	}

	return mcpJSONResult(out), out, nil
}

func mcpJSONResult(v any) *mcp.CallToolResult {
	b, _ := json.MarshalIndent(v, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(b)},
		},
	}
}

func mcpErrorResult(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: err.Error()},
		},
	}
}
