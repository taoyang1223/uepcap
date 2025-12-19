package protocol

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"

	"uepcap/internal/tshark"
)

// IMSIScanner scans pcap files for IMSI values
type IMSIScanner struct {
	imsiPattern *regexp.Regexp
}

// NewIMSIScanner creates a new IMSI scanner
func NewIMSIScanner() *IMSIScanner {
	return &IMSIScanner{
		imsiPattern: regexp.MustCompile(`\b([0-9]{14,15})\b`),
	}
}

// ScanIMSIs scans a pcap file for all unique IMSI values
// Optimized: uses single tshark call with comprehensive field extraction
func (s *IMSIScanner) ScanIMSIs(ctx context.Context, pcapFile string) ([]string, error) {
	var mu sync.Mutex
	imsiSet := make(map[string]bool)

	// Run both strategies in parallel
	var wg sync.WaitGroup
	wg.Add(2)

	// Strategy 1: Fast field extraction (single tshark call)
	go func() {
		defer wg.Done()
		results := s.scanByFieldsFast(ctx, pcapFile)
		mu.Lock()
		for imsi := range results {
			imsiSet[imsi] = true
		}
		mu.Unlock()
	}()

	// Strategy 2: Verbose scan with combined filter (single tshark call)
	go func() {
		defer wg.Done()
		results := s.scanVerboseCombined(ctx, pcapFile)
		mu.Lock()
		for imsi := range results {
			imsiSet[imsi] = true
		}
		mu.Unlock()
	}()

	wg.Wait()

	// Convert to sorted list
	imsiList := make([]string, 0, len(imsiSet))
	for imsi := range imsiSet {
		imsiList = append(imsiList, imsi)
	}
	sort.Strings(imsiList)

	return imsiList, nil
}

// scanByFieldsFast extracts IMSI using a single tshark call with all known fields
func (s *IMSIScanner) scanByFieldsFast(ctx context.Context, pcapFile string) map[string]bool {
	imsiSet := make(map[string]bool)

	// Comprehensive IMSI fields - extracted in one call
	// Note: gtpv2.imsi is NOT a valid field, GTPv2 IMSI is extracted via e212.imsi
	fields := []string{
		"e212.imsi",        // Generic E.212 IMSI (covers GTPv2, S1AP, NGAP, etc.)
		"gsm_a.imsi",       // GSM/UMTS IMSI
		"nas_5gs.mm.imsi",  // 5G NAS IMSI
		"nas_eps.emm.imsi", // LTE NAS IMSI
		"pfcp.user_id",     // PFCP User ID (may contain IMSI)
	}

	// Single tshark call with combined filter for signaling protocols
	filter := "gtpv2 or s1ap or ngap or nas_5gs or nas_eps or diameter or pfcp"
	result, err := tshark.TsharkFields(ctx, pcapFile, filter, fields)
	if err != nil {
		return imsiSet
	}

	// Parse field output efficiently
	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if s.isValidIMSI(part) {
				imsiSet[part] = true
			}
		}
	}

	return imsiSet
}

// scanVerboseCombined uses a single verbose tshark call with combined filter
func (s *IMSIScanner) scanVerboseCombined(ctx context.Context, pcapFile string) map[string]bool {
	imsiSet := make(map[string]bool)

	// Combined filter for all protocols that may contain IMSI
	// Focus on messages that typically contain IMSI:
	// - PFCP Session Establishment Request (msg_type=50)
	// - Initial UE Message (ngap.procedureCode==15)
	// - Attach Request, etc.
	filter := "pfcp.msg_type == 50 or ngap.procedureCode == 15 or s1ap.procedureCode == 12 or gtpv2.message_type == 32"

	result, err := tshark.TsharkVerbose(ctx, pcapFile, filter)
	if err != nil {
		return imsiSet
	}

	// Compile patterns once and reuse
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`IMSI:\s*([0-9]{14,15})`),
		regexp.MustCompile(`(?i)imsi["\s:=]+([0-9]{14,15})`),
		regexp.MustCompile(`SUPI:\s*imsi-([0-9]{14,15})`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(result.Stdout, -1)
		for _, match := range matches {
			if len(match) > 1 && s.isValidIMSI(match[1]) {
				imsiSet[match[1]] = true
			}
		}
	}

	return imsiSet
}

// ScanIMSIsStream scans IMSI values and streams results through a channel
// Results are sent immediately as they're found
func (s *IMSIScanner) ScanIMSIsStream(ctx context.Context, pcapFile string, imsiChan chan<- string) error {
	defer close(imsiChan)

	var mu sync.Mutex
	seen := make(map[string]bool)

	// Helper to send unique IMSI
	sendIMSI := func(imsi string) {
		mu.Lock()
		if !seen[imsi] {
			seen[imsi] = true
			mu.Unlock()
			select {
			case imsiChan <- imsi:
			case <-ctx.Done():
			}
		} else {
			mu.Unlock()
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Strategy 1: Fast field extraction - usually completes first
	go func() {
		defer wg.Done()
		s.scanByFieldsStream(ctx, pcapFile, sendIMSI)
	}()

	// Strategy 2: Verbose scan for additional matches
	go func() {
		defer wg.Done()
		s.scanVerboseStream(ctx, pcapFile, sendIMSI)
	}()

	wg.Wait()
	return nil
}

// scanByFieldsStream extracts IMSI using field extraction and streams results
func (s *IMSIScanner) scanByFieldsStream(ctx context.Context, pcapFile string, sendIMSI func(string)) {
	// Note: gtpv2.imsi is NOT a valid field, GTPv2 IMSI is extracted via e212.imsi
	fields := []string{
		"e212.imsi",
		"gsm_a.imsi",
		"nas_5gs.mm.imsi",
		"nas_eps.emm.imsi",
		"pfcp.user_id",
	}

	filter := "gtpv2 or s1ap or ngap or nas_5gs or nas_eps or diameter or pfcp"
	result, err := tshark.TsharkFields(ctx, pcapFile, filter, fields)
	if err != nil {
		return
	}

	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if s.isValidIMSI(part) {
				sendIMSI(part)
			}
		}
	}
}

// scanVerboseStream uses verbose output and streams IMSI results
func (s *IMSIScanner) scanVerboseStream(ctx context.Context, pcapFile string, sendIMSI func(string)) {
	filter := "pfcp.msg_type == 50 or ngap.procedureCode == 15 or s1ap.procedureCode == 12 or gtpv2.message_type == 32"

	result, err := tshark.TsharkVerbose(ctx, pcapFile, filter)
	if err != nil {
		return
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`IMSI:\s*([0-9]{14,15})`),
		regexp.MustCompile(`(?i)imsi["\s:=]+([0-9]{14,15})`),
		regexp.MustCompile(`SUPI:\s*imsi-([0-9]{14,15})`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(result.Stdout, -1)
		for _, match := range matches {
			if len(match) > 1 && s.isValidIMSI(match[1]) {
				sendIMSI(match[1])
			}
		}
	}
}

// isValidIMSI checks if a string looks like a valid IMSI
func (s *IMSIScanner) isValidIMSI(val string) bool {
	// IMSI is 14-15 digits
	if len(val) < 14 || len(val) > 15 {
		return false
	}
	// Must be all digits
	for _, c := range val {
		if c < '0' || c > '9' {
			return false
		}
	}
	// Common test IMSI prefixes to filter out
	if strings.HasPrefix(val, "00000000") {
		return false
	}
	return true
}
