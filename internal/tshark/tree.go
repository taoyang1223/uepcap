package tshark

import (
	"context"
	"fmt"
	"strings"
)

// ProtocolTreeConfig holds configuration for protocol tree extraction
type ProtocolTreeConfig struct {
	// AllowedProtocols is the whitelist of protocols that can be extracted
	AllowedProtocols map[string]bool
	// ProtocolHeaders maps protocol ID to possible header line prefixes
	// Used to find where the protocol tree starts in tshark -O output
	ProtocolHeaders map[string][]string
}

// DefaultProtocolTreeConfig returns default configuration
func DefaultProtocolTreeConfig() *ProtocolTreeConfig {
	return &ProtocolTreeConfig{
		AllowedProtocols: map[string]bool{
			"ngap":    true,
			"s1ap":    true,
			"pfcp":    true,
			"gtpv2":   true,
			"gtp":     true,
			"nas-5gs": true,
			"nas-eps": true,
			"diameter": true,
			"sctp":    true,
			"f1ap":    true,
			"e1ap":    true,
			"xnap":    true,
			"x2ap":    true,
		},
		ProtocolHeaders: map[string][]string{
			"ngap":    {"NG Application Protocol"},
			"s1ap":    {"S1 Application Protocol"},
			"pfcp":    {"Packet Forwarding Control Protocol"},
			"gtpv2":   {"GPRS Tunneling Protocol V2"},
			"gtp":     {"GPRS Tunneling Protocol"},
			"nas-5gs": {"Non-Access-Stratum 5GS (NAS)5GS", "NAS-5GS"},
			"nas-eps": {"Non-Access-Stratum (NAS)PDU", "NAS-EPS"},
			"diameter": {"Diameter Protocol"},
			"sctp":    {"Stream Control Transmission Protocol"},
			"f1ap":    {"F1 Application Protocol"},
			"e1ap":    {"E1 Application Protocol"},
			"xnap":    {"XnAP"},
			"x2ap":    {"X2 Application Protocol"},
		},
	}
}

// globalTreeConfig is the default configuration instance
var globalTreeConfig = DefaultProtocolTreeConfig()

// IsAllowedProtocol checks if a protocol is in the whitelist
func IsAllowedProtocol(proto string) bool {
	return globalTreeConfig.AllowedProtocols[proto]
}

// GetAllowedProtocols returns a list of allowed protocol names
func GetAllowedProtocols() []string {
	protos := make([]string, 0, len(globalTreeConfig.AllowedProtocols))
	for p := range globalTreeConfig.AllowedProtocols {
		protos = append(protos, p)
	}
	return protos
}

// ProtocolTreeResult holds the result of protocol tree extraction
type ProtocolTreeResult struct {
	Frame    int    `json:"frame"`
	Protocol string `json:"protocol"`
	Tree     string `json:"tree"`
	Cached   bool   `json:"cached"`
}

// TsharkProtocolTree extracts the protocol tree text for a specific frame.
// It runs tshark -O <proto> and filters the output to only include the target protocol's tree.
// The output is similar to what Wireshark shows when you expand a protocol in the packet details pane.
func TsharkProtocolTree(ctx context.Context, pcapFile string, frameNumber int, protocol string) (*ProtocolTreeResult, error) {
	// Validate protocol
	if !IsAllowedProtocol(protocol) {
		return nil, fmt.Errorf("protocol %q is not in the allowed list", protocol)
	}

	// Build tshark command
	// tshark -r <pcap> -Y "frame.number==X" -O <proto>
	// Note: We do NOT use -c 1 because it limits reading to the first N frames from the file,
	// not the first N frames matching the filter. With -c 1, frame.number > 1 would never match.
	filter := fmt.Sprintf("frame.number==%d", frameNumber)
	args := []string{
		"-r", pcapFile,
		"-Y", filter,
		"-O", protocol,
	}

	// Add NAS decryption preferences
	args = appendNASDecryptPrefs(args, protocol, []string{protocol})

	result, err := Exec(ctx, "tshark", args...)
	if err != nil {
		return nil, fmt.Errorf("tshark execution failed: %w", err)
	}

	if result.ExitCode != 0 {
		errMsg := strings.TrimSpace(result.Stderr)
		if errMsg == "" {
			errMsg = fmt.Sprintf("tshark exited with code %d", result.ExitCode)
		}
		return nil, fmt.Errorf("tshark failed: %s", errMsg)
	}

	// Check if any output was produced
	stdout := strings.TrimSpace(result.Stdout)
	if stdout == "" {
		return nil, fmt.Errorf("no packet found for frame %d with protocol %s", frameNumber, protocol)
	}

	// Extract only the protocol tree part (remove Frame, IP, SCTP, etc.)
	tree := extractProtocolTree(stdout, protocol)
	if tree == "" {
		return nil, fmt.Errorf("protocol %s tree not found in frame %d output", protocol, frameNumber)
	}

	return &ProtocolTreeResult{
		Frame:    frameNumber,
		Protocol: protocol,
		Tree:     tree,
		Cached:   false,
	}, nil
}

// extractProtocolTree extracts only the target protocol's tree from tshark -O output.
// It finds the header line for the protocol and returns everything from that line onward.
func extractProtocolTree(output string, protocol string) string {
	lines := strings.Split(output, "\n")

	// Get possible header prefixes for this protocol
	headers, ok := globalTreeConfig.ProtocolHeaders[protocol]
	if !ok {
		// Fallback: use protocol name as header
		headers = []string{protocol}
	}

	// Find the line where the protocol tree starts
	startIdx := -1
	for i, line := range lines {
		for _, header := range headers {
			if strings.HasPrefix(line, header) || strings.Contains(line, header) {
				startIdx = i
				break
			}
		}
		if startIdx >= 0 {
			break
		}
	}

	if startIdx < 0 {
		// Try a more lenient match: find any line that looks like a protocol header
		// Protocol headers typically start at column 0 (no leading spaces) and contain ":"
		for i, line := range lines {
			if len(line) > 0 && line[0] != ' ' && strings.Contains(line, ":") {
				// Check if this might be a protocol layer (not Frame/Ethernet/IP/UDP/TCP/SCTP)
				lowerLine := strings.ToLower(line)
				skipPrefixes := []string{"frame", "ethernet", "internet protocol", "user datagram",
					"transmission control", "stream control", "linux cooked"}
				shouldSkip := false
				for _, prefix := range skipPrefixes {
					if strings.HasPrefix(lowerLine, prefix) {
						shouldSkip = true
						break
					}
				}
				if !shouldSkip && i > 0 {
					// This might be our protocol
					startIdx = i
					break
				}
			}
		}
	}

	if startIdx < 0 {
		return ""
	}

	// Return from startIdx to end
	return strings.Join(lines[startIdx:], "\n")
}

// MapDisplayProtocolToTsharkFilter maps display protocol names (from tshark columns)
// to tshark filter protocol names.
// E.g., "NGAP/NAS-5GS" -> "ngap", "PFCP" -> "pfcp"
func MapDisplayProtocolToTsharkFilter(displayProtocol string) string {
	displayProtocol = strings.ToLower(displayProtocol)

	// Handle compound protocols like "NGAP/NAS-5GS"
	if strings.Contains(displayProtocol, "/") {
		parts := strings.Split(displayProtocol, "/")
		displayProtocol = parts[0]
	}

	// Remove any suffix like " (encrypted)"
	if idx := strings.Index(displayProtocol, " "); idx > 0 {
		displayProtocol = displayProtocol[:idx]
	}

	// Map common display names to tshark filter names
	mapping := map[string]string{
		"ngap":         "ngap",
		"s1ap":         "s1ap",
		"pfcp":         "pfcp",
		"gtpv2":        "gtpv2",
		"gtp":          "gtp",
		"nas-5gs":      "nas-5gs",
		"nas-eps":      "nas-eps",
		"diameter":     "diameter",
		"sctp":         "sctp",
		"f1ap":         "f1ap",
		"e1ap":         "e1ap",
		"xnap":         "xnap",
		"x2ap":         "x2ap",
		// Additional aliases
		"gtp-u":        "gtp",
		"gtp-c":        "gtpv2",
		"gtpv2-c":      "gtpv2",
	}

	if mapped, ok := mapping[displayProtocol]; ok {
		return mapped
	}

	// Return as-is if not in mapping (will be validated by IsAllowedProtocol)
	return displayProtocol
}

// TsharkProtocolTreeBatch extracts protocol trees for multiple frames in a single tshark call.
// This is more efficient than calling TsharkProtocolTree for each frame individually.
// It runs tshark with a filter matching the given frames and protocol, then splits the output
// by "Frame X:" boundaries to extract each frame's protocol tree.
//
// Parameters:
//   - ctx: context for cancellation/timeout
//   - pcapFile: path to the pcap file
//   - frameNumbers: list of frame numbers to extract (Wireshark frame.number values)
//   - protocol: the protocol to extract (must be in allowed list)
//
// Returns a map of frameNumber -> protocol tree string.
// Frames that don't match or have no protocol tree are omitted from the result.
func TsharkProtocolTreeBatch(ctx context.Context, pcapFile string, frameNumbers []int, protocol string) (map[int]string, error) {
	if len(frameNumbers) == 0 {
		return map[int]string{}, nil
	}

	// Validate protocol
	if !IsAllowedProtocol(protocol) {
		return nil, fmt.Errorf("protocol %q is not in the allowed list", protocol)
	}

	// Build display filter for multiple frames: frame.number==1 or frame.number==2 or ...
	// For large lists, this could be slow, but typically flow diagrams have <200 frames
	filterParts := make([]string, len(frameNumbers))
	for i, fn := range frameNumbers {
		filterParts[i] = fmt.Sprintf("frame.number==%d", fn)
	}
	filter := strings.Join(filterParts, " or ")

	args := []string{
		"-r", pcapFile,
		"-Y", filter,
		"-O", protocol,
	}

	// Add NAS decryption preferences
	args = appendNASDecryptPrefs(args, protocol, []string{protocol})

	result, err := Exec(ctx, "tshark", args...)
	if err != nil {
		return nil, fmt.Errorf("tshark batch execution failed: %w", err)
	}

	if result.ExitCode != 0 {
		errMsg := strings.TrimSpace(result.Stderr)
		if errMsg == "" {
			errMsg = fmt.Sprintf("tshark exited with code %d", result.ExitCode)
		}
		return nil, fmt.Errorf("tshark batch failed: %s", errMsg)
	}

	stdout := result.Stdout
	if strings.TrimSpace(stdout) == "" {
		return map[int]string{}, nil
	}

	// Split output by frame boundaries and extract protocol trees
	return splitAndExtractTrees(stdout, protocol)
}

// splitAndExtractTrees splits tshark -O output containing multiple frames
// and extracts the protocol tree for each frame.
// tshark -O output format for multiple frames:
//
//	Frame 1: ...
//	  ... frame details ...
//	Protocol Header:
//	  ... protocol tree ...
//
//	Frame 2: ...
//	  ... frame details ...
//	Protocol Header:
//	  ... protocol tree ...
//
// Returns map of frameNumber -> protocol tree string.
func splitAndExtractTrees(output string, protocol string) (map[int]string, error) {
	result := make(map[int]string)
	lines := strings.Split(output, "\n")

	// Find all "Frame N:" boundaries
	type frameRange struct {
		number   int
		startIdx int
	}
	var frames []frameRange

	for i, line := range lines {
		if strings.HasPrefix(line, "Frame ") && strings.Contains(line, ":") {
			// Parse frame number from "Frame N: ..."
			// Format: "Frame 123: 456 bytes on wire ..."
			parts := strings.SplitN(line, ":", 2)
			if len(parts) >= 1 {
				numStr := strings.TrimPrefix(parts[0], "Frame ")
				numStr = strings.TrimSpace(numStr)
				var frameNum int
				if _, err := fmt.Sscanf(numStr, "%d", &frameNum); err == nil && frameNum > 0 {
					frames = append(frames, frameRange{number: frameNum, startIdx: i})
				}
			}
		}
	}

	// Extract each frame's content and get its protocol tree
	for i, fr := range frames {
		var endIdx int
		if i+1 < len(frames) {
			endIdx = frames[i+1].startIdx
		} else {
			endIdx = len(lines)
		}

		// Get this frame's content
		frameContent := strings.Join(lines[fr.startIdx:endIdx], "\n")

		// Extract protocol tree from this frame's content
		tree := extractProtocolTree(frameContent, protocol)
		if tree != "" {
			result[fr.number] = tree
		}
	}

	return result, nil
}

