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
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"uepcap/internal/packet"
	"uepcap/internal/protocol"
	"uepcap/internal/tshark"
)

// 默认数据目录
var dataDir = "./data"

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
	PcapFile       string `json:"pcap_file,omitempty" jsonschema:"PCAP/PCAPNG 文件路径（可选，不提供则自动使用后端最新上传的文件）"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"超时时间（秒），默认 300"`
}

type listIMSIsOut struct {
	IMSIs    []string `json:"imsis"`
	PcapFile string   `json:"pcap_file"`
}

type imsiBriefArgs struct {
	PcapFile       string   `json:"pcap_file,omitempty" jsonschema:"PCAP/PCAPNG 文件路径（可选，不提供则自动使用后端最新上传的文件）"`
	IMSI           string   `json:"imsi" jsonschema:"目标 IMSI（14~15 位数字）"`
	Protocols      []string `json:"protocols,omitempty" jsonschema:"协议列表：ngap/pfcp/s1ap/gtpv2/gtpu/ueip；默认全选"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"超时时间（秒），默认 120"`
}

type imsiBriefOut struct {
	IMSI           string                 `json:"imsi"`
	PcapFile       string                 `json:"pcap_file"`
	Protocols      []string               `json:"protocols"`
	Filters        map[string]string      `json:"filters"`
	CombinedFilter string                 `json:"combined_filter"`
	UEIPv4         string                 `json:"ue_ipv4,omitempty"`
	Packets        []packet.CompactPacket `json:"packets,omitempty"`
	PacketCount    int                    `json:"packet_count"`
}

// PcapInfo 表示一个可用的 pcap 文件信息
type PcapInfo struct {
	JobID     string    `json:"job_id"`
	Path      string    `json:"path"`
	ModTime   time.Time `json:"mod_time"`
	SizeBytes int64     `json:"size_bytes"`
}

type listPcapsArgs struct{}

type listPcapsOut struct {
	Pcaps   []PcapInfo `json:"pcaps"`
	DataDir string     `json:"data_dir"`
}

func main() {
	var (
		name       = flag.String("name", "uepcap-mcp", "MCP server name")
		version    = flag.String("version", "v0.1.0", "MCP server version")
		dataDirArg = flag.String("data-dir", "./data", "数据目录路径")
	)
	flag.Parse()

	// 设置数据目录
	dataDir = *dataDirArg

	// 依赖检查：tshark/mergecap
	if err := checkDependencies(); err != nil {
		log.Fatalf("依赖检查失败: %v", err)
	}

	server := mcp.NewServer(&mcp.Implementation{Name: *name, Version: *version}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "uepcap_list_pcaps",
		Description: "列出后端已上传的所有 PCAP 文件（按修改时间降序排列）。",
	}, handleListPcaps)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "uepcap_list_imsis",
		Description: "从 PCAP/PCAPNG 文件中扫描并返回 IMSI 列表（去重、排序）。pcap_file 可选，不提供则自动使用最新上传的文件。",
	}, handleListIMSIs)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "uepcap_imsi_brief",
		Description: "根据 IMSI 解析关联协议的 display filter，并返回简要 JSON（包含 per-protocol filters、combined_filter 及简化的包数据）。pcap_file 可选，不提供则自动使用最新上传的文件。",
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

// findAvailablePcaps 查找数据目录下所有可用的 pcap 文件
func findAvailablePcaps() ([]PcapInfo, error) {
	tmpDir := filepath.Join(dataDir, "tmp")
	if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
		return nil, nil // 目录不存在，返回空列表
	}

	var pcaps []PcapInfo

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("读取数据目录失败: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		jobID := entry.Name()
		mergedPcap := filepath.Join(tmpDir, jobID, "merged.pcap")
		if st, err := os.Stat(mergedPcap); err == nil && !st.IsDir() {
			pcaps = append(pcaps, PcapInfo{
				JobID:     jobID,
				Path:      mergedPcap,
				ModTime:   st.ModTime(),
				SizeBytes: st.Size(),
			})
		}
	}

	// 按修改时间降序排列（最新的在前面）
	sort.Slice(pcaps, func(i, j int) bool {
		return pcaps[i].ModTime.After(pcaps[j].ModTime)
	})

	return pcaps, nil
}

// findLatestPcap 查找最新上传的 pcap 文件
func findLatestPcap() (string, error) {
	pcaps, err := findAvailablePcaps()
	if err != nil {
		return "", err
	}
	if len(pcaps) == 0 {
		return "", fmt.Errorf("没有找到已上传的 PCAP 文件，请先通过 Web 界面上传或指定 pcap_file 参数")
	}
	return pcaps[0].Path, nil
}

func validatePcapFile(path string) (string, error) {
	// 如果路径为空，自动查找最新的 pcap 文件
	if strings.TrimSpace(path) == "" {
		return findLatestPcap()
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

// handleListPcaps 处理列出可用 pcap 文件的请求
func handleListPcaps(ctx context.Context, _ *mcp.CallToolRequest, args listPcapsArgs) (*mcp.CallToolResult, listPcapsOut, error) {
	pcaps, err := findAvailablePcaps()
	if err != nil {
		return mcpErrorResult(err), listPcapsOut{}, nil
	}

	absDataDir, _ := filepath.Abs(dataDir)
	out := listPcapsOut{
		Pcaps:   pcaps,
		DataDir: absDataDir,
	}

	if len(pcaps) == 0 {
		out.Pcaps = []PcapInfo{} // 确保返回空数组而不是 null
	}

	return mcpJSONResult(out), out, nil
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

	// 确保返回空数组而不是 null
	if imsis == nil {
		imsis = []string{}
	}
	out := listIMSIsOut{
		IMSIs:    imsis,
		PcapFile: pcapFile,
	}
	return mcpJSONResult(out), out, nil
}

// 支持的应用层协议列表
var applicationProtocols = []string{"ngap", "nas-5gs", "pfcp", "s1ap", "gtpv2", "gtp"}

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

	// 获取简化的包 JSON 数据
	if combined != "" {
		result, err := tshark.TsharkCompactJSON(ctx, pcapFile, combined, applicationProtocols)
		if err == nil && result.ExitCode == 0 {
			compactJSON, err := packet.SimplifyPacketsJSON(result.Stdout)
			if err == nil {
				// 解析为 CompactPacket 数组
				var packets []packet.CompactPacket
				if json.Unmarshal([]byte(compactJSON), &packets) == nil {
					out.Packets = packets
					out.PacketCount = len(packets)
				}
			}
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
