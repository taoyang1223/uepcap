package protocol

import (
	"context"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

// IMSIScanner scans pcap files for IMSI values
type IMSIScanner struct {
	imsiPattern *regexp.Regexp
}

var imsiFieldCandidates = []string{
	"e212.imsi",        // Generic E.212 IMSI (covers GTPv2, S1AP, NGAP, etc.)
	"gsm_a.imsi",       // GSM/UMTS IMSI
	"nas_5gs.mm.imsi",  // 5G NAS IMSI on newer Wireshark versions
	"nas_eps.emm.imsi", // LTE NAS IMSI on newer Wireshark versions
	"pfcp.user_id",     // PFCP User ID on newer Wireshark versions
}

var (
	imsiFieldsOnce sync.Once
	imsiFields     []string
)

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
	log.Printf("[IMSIScanner] scanByFieldsFast starting, pcapFile: %s", pcapFile)

	fields := supportedIMSIFields(ctx)
	if len(fields) == 0 {
		return imsiSet
	}

	// Single tshark call with combined filter for signaling protocols
	filter := "gtpv2 or s1ap or ngap or nas_5gs or nas_eps or diameter or pfcp"
	log.Printf("[IMSIScanner] scanByFieldsFast tshark filter: %s", filter)
	log.Printf("[IMSIScanner] scanByFieldsFast tshark fields: %v", fields)

	result, err := tshark.TsharkFields(ctx, pcapFile, filter, fields)
	if err != nil {
		log.Printf("[IMSIScanner] scanByFieldsFast tshark error: %v", err)
		return imsiSet
	}

	log.Printf("[IMSIScanner] scanByFieldsFast tshark exitCode: %d, stderr: %s", result.ExitCode, result.Stderr)
	if result.ExitCode != 0 {
		log.Printf("[IMSIScanner] scanByFieldsFast tshark non-zero exit code")
	}

	// Parse field output efficiently
	lines := strings.Split(result.Stdout, "\n")
	log.Printf("[IMSIScanner] scanByFieldsFast got %d lines of output", len(lines))

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

	log.Printf("[IMSIScanner] scanByFieldsFast found %d IMSIs", len(imsiSet))
	return imsiSet
}

// scanVerboseCombined uses a single verbose tshark call with combined filter
func (s *IMSIScanner) scanVerboseCombined(ctx context.Context, pcapFile string) map[string]bool {
	imsiSet := make(map[string]bool)
	log.Printf("[IMSIScanner] scanVerboseCombined starting, pcapFile: %s", pcapFile)

	// Combined filter for all protocols that may contain IMSI
	// Focus on messages that typically contain IMSI:
	// - PFCP Session Establishment Request (msg_type=50)
	// - Initial UE Message (ngap.procedureCode==15)
	// - Attach Request, etc.
	filter := "pfcp.msg_type == 50 or ngap.procedureCode == 15 or s1ap.procedureCode == 12 or gtpv2.message_type == 32"
	log.Printf("[IMSIScanner] scanVerboseCombined tshark filter: %s", filter)

	result, err := tshark.TsharkVerbose(ctx, pcapFile, filter)
	if err != nil {
		log.Printf("[IMSIScanner] scanVerboseCombined tshark error: %v", err)
		return imsiSet
	}

	log.Printf("[IMSIScanner] scanVerboseCombined tshark exitCode: %d, stderr len: %d, stdout len: %d",
		result.ExitCode, len(result.Stderr), len(result.Stdout))
	if result.ExitCode != 0 {
		log.Printf("[IMSIScanner] scanVerboseCombined tshark stderr: %s", result.Stderr)
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

	log.Printf("[IMSIScanner] scanVerboseCombined found %d IMSIs", len(imsiSet))
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
	log.Printf("[IMSIScanner] scanByFieldsStream starting, pcapFile: %s", pcapFile)

	fields := supportedIMSIFields(ctx)
	if len(fields) == 0 {
		log.Printf("[IMSIScanner] scanByFieldsStream skipped: no supported IMSI fields")
		return
	}

	filter := "gtpv2 or s1ap or ngap or nas_5gs or nas_eps or diameter or pfcp"
	log.Printf("[IMSIScanner] scanByFieldsStream tshark filter: %s", filter)

	result, err := tshark.TsharkFields(ctx, pcapFile, filter, fields)
	if err != nil {
		log.Printf("[IMSIScanner] scanByFieldsStream tshark error: %v", err)
		return
	}

	log.Printf("[IMSIScanner] scanByFieldsStream tshark exitCode: %d, stderr: %s", result.ExitCode, result.Stderr)

	lines := strings.Split(result.Stdout, "\n")
	log.Printf("[IMSIScanner] scanByFieldsStream got %d lines", len(lines))

	foundCount := 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if s.isValidIMSI(part) {
				foundCount++
				sendIMSI(part)
			}
		}
	}
	log.Printf("[IMSIScanner] scanByFieldsStream completed, found %d IMSIs", foundCount)
}

// scanVerboseStream uses verbose output and streams IMSI results
func (s *IMSIScanner) scanVerboseStream(ctx context.Context, pcapFile string, sendIMSI func(string)) {
	log.Printf("[IMSIScanner] scanVerboseStream starting, pcapFile: %s", pcapFile)

	filter := "pfcp.msg_type == 50 or ngap.procedureCode == 15 or s1ap.procedureCode == 12 or gtpv2.message_type == 32"
	log.Printf("[IMSIScanner] scanVerboseStream tshark filter: %s", filter)

	result, err := tshark.TsharkVerbose(ctx, pcapFile, filter)
	if err != nil {
		log.Printf("[IMSIScanner] scanVerboseStream tshark error: %v", err)
		return
	}

	log.Printf("[IMSIScanner] scanVerboseStream tshark exitCode: %d, stderr len: %d, stdout len: %d",
		result.ExitCode, len(result.Stderr), len(result.Stdout))
	if result.ExitCode != 0 {
		log.Printf("[IMSIScanner] scanVerboseStream tshark stderr: %s", result.Stderr)
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`IMSI:\s*([0-9]{14,15})`),
		regexp.MustCompile(`(?i)imsi["\s:=]+([0-9]{14,15})`),
		regexp.MustCompile(`SUPI:\s*imsi-([0-9]{14,15})`),
	}

	foundCount := 0
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(result.Stdout, -1)
		for _, match := range matches {
			if len(match) > 1 && s.isValidIMSI(match[1]) {
				foundCount++
				sendIMSI(match[1])
			}
		}
	}
	log.Printf("[IMSIScanner] scanVerboseStream completed, found %d IMSIs", foundCount)
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

func supportedIMSIFields(ctx context.Context) []string {
	imsiFieldsOnce.Do(func() {
		imsiFields = detectSupportedIMSIFields(ctx)
	})
	return append([]string(nil), imsiFields...)
}

func detectSupportedIMSIFields(parent context.Context) []string {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	result, err := tshark.Exec(ctx, "tshark", "-G", "fields")
	if err != nil || result.ExitCode != 0 {
		log.Printf("[IMSIScanner] failed to detect tshark IMSI fields, using e212.imsi only: %v", err)
		return []string{"e212.imsi"}
	}

	available := make(map[string]bool)
	for _, line := range strings.Split(result.Stdout, "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) >= 3 {
			available[cols[2]] = true
		}
	}

	fields := make([]string, 0, len(imsiFieldCandidates))
	for _, field := range imsiFieldCandidates {
		if available[field] {
			fields = append(fields, field)
		}
	}
	if len(fields) == 0 && available["e212.imsi"] {
		fields = append(fields, "e212.imsi")
	}
	log.Printf("[IMSIScanner] supported IMSI fields: %v", fields)
	return fields
}
