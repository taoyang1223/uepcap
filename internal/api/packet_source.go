package api

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

var packetSourceFields = []string{
	"frame.time_epoch",
	"ip.src",
	"ip.dst",
	"ipv6.src",
	"ipv6.dst",
}

const packetSourceFilter = "ngap || s1ap || nas-5gs || pfcp || gtpv2"

type sourceCapture struct {
	name string
	path string
}

type packetSourceIndex struct {
	singleSource string
	sources      map[string]map[string]bool
}

func (h *Handler) packetSourceIndex(ctx context.Context, jobID string, originalFiles []string, mergedPcap string) (*packetSourceIndex, error) {
	value, err := h.analysis.getOrCompute(ctx, jobID+"|packet-source-v1", func(ctx context.Context) (any, error) {
		return buildPacketSourceIndex(ctx, originalFiles, mergedPcap)
	})
	if err != nil {
		return nil, err
	}
	index, ok := value.(*packetSourceIndex)
	if !ok {
		return nil, fmt.Errorf("invalid packet source index")
	}
	return index, nil
}

func (h *Handler) packetSourceIndexBestEffort(ctx context.Context, jobID string, originalFiles []string, mergedPcap string) *packetSourceIndex {
	index, err := h.packetSourceIndex(ctx, jobID, originalFiles, mergedPcap)
	if err != nil {
		log.Printf("[PacketSource] source lookup unavailable for job %s: %v", jobID, err)
		return nil
	}
	return index
}

func buildPacketSourceIndex(ctx context.Context, originalFiles []string, mergedPcap string) (*packetSourceIndex, error) {
	captures := resolveSourceCaptures(originalFiles, mergedPcap)
	if len(captures) == 0 {
		return nil, fmt.Errorf("no readable source captures")
	}
	if len(captures) == 1 && len(originalFiles) <= 1 {
		return &packetSourceIndex{singleSource: captures[0].name}, nil
	}
	if len(captures) != len(originalFiles) {
		return nil, fmt.Errorf("resolved %d of %d source captures", len(captures), len(originalFiles))
	}

	index := &packetSourceIndex{sources: make(map[string]map[string]bool)}
	for _, capture := range captures {
		result, err := tshark.TsharkFieldsStream(ctx, capture.path, packetSourceFilter, packetSourceFields, func(line string) error {
			timestamp, sourceIP, destinationIP, ok := parsePacketSourceLine(line)
			if ok {
				index.add(timestamp, sourceIP, destinationIP, capture.name)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("index source capture %s: %w", capture.name, err)
		}
		if result.ExitCode != 0 {
			return nil, fmt.Errorf("index source capture %s: %s", capture.name, strings.TrimSpace(result.Stderr))
		}
	}
	return index, nil
}

func (i *packetSourceIndex) add(timestamp time.Time, sourceIP, destinationIP, filename string) {
	key := packetSourceKey(timestamp, sourceIP, destinationIP)
	if key == "" || filename == "" {
		return
	}
	if i.sources[key] == nil {
		i.sources[key] = make(map[string]bool)
	}
	i.sources[key][filename] = true
}

func (i *packetSourceIndex) lookup(timestamp time.Time, sourceIP, destinationIP string) string {
	if i == nil {
		return ""
	}
	if i.singleSource != "" {
		return i.singleSource
	}
	return uniqueSource(i.sources[packetSourceKey(timestamp, sourceIP, destinationIP)])
}

func packetSourceKey(timestamp time.Time, sourceIP, destinationIP string) string {
	if timestamp.IsZero() || net.ParseIP(sourceIP) == nil || net.ParseIP(destinationIP) == nil {
		return ""
	}
	return fmt.Sprintf("%d|%s|%s", timestamp.UnixNano(), sourceIP, destinationIP)
}

func uniqueSource(sources map[string]bool) string {
	if len(sources) != 1 {
		return ""
	}
	for source := range sources {
		return source
	}
	return ""
}

func parsePacketSourceLine(line string) (time.Time, string, string, bool) {
	cols := strings.Split(line, "\t")
	for len(cols) < len(packetSourceFields) {
		cols = append(cols, "")
	}
	timestamp := parsePacketSourceEpoch(cols[0])
	sourceIP := firstPacketSourceValue(cols[1], cols[3])
	destinationIP := firstPacketSourceValue(cols[2], cols[4])
	return timestamp, sourceIP, destinationIP, !timestamp.IsZero() && net.ParseIP(sourceIP) != nil && net.ParseIP(destinationIP) != nil
}

func parsePacketSourceEpoch(value string) time.Time {
	value = firstPacketSourceValue(value)
	epoch, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return time.Time{}
	}
	seconds := int64(epoch)
	nanoseconds := int64((epoch - float64(seconds)) * 1e9)
	return time.Unix(seconds, nanoseconds)
}

func firstPacketSourceValue(values ...string) string {
	for _, value := range values {
		parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' })
		if len(parts) == 0 {
			continue
		}
		if part := strings.TrimSpace(parts[0]); part != "" {
			return strings.Trim(part, `"`)
		}
	}
	return ""
}

func resolveSourceCaptures(originalFiles []string, mergedPcap string) []sourceCapture {
	if len(originalFiles) <= 1 {
		name := filepath.Base(mergedPcap)
		if len(originalFiles) == 1 && filepath.Base(originalFiles[0]) != "." {
			name = filepath.Base(originalFiles[0])
		}
		if name == "" || name == "." {
			return nil
		}
		return []sourceCapture{{name: name, path: mergedPcap}}
	}

	captures := make([]sourceCapture, 0, len(originalFiles))
	seenPaths := make(map[string]bool, len(originalFiles))
	for _, original := range originalFiles {
		name := filepath.Base(strings.TrimSpace(original))
		if name == "" || name == "." {
			continue
		}
		path := original
		if !isRegularCapture(path) && strings.HasSuffix(strings.ToLower(path), ".gz") {
			path = strings.TrimSuffix(path, filepath.Ext(path))
		}
		if !isRegularCapture(path) || seenPaths[path] {
			continue
		}
		seenPaths[path] = true
		captures = append(captures, sourceCapture{name: name, path: path})
	}
	return captures
}

func isRegularCapture(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
