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
	"e212.imsi",            // Generic E.212 IMSI (covers GTPv2, S1AP, NGAP, etc.)
	"gsm_a.imsi",           // GSM/UMTS IMSI
	"nas_5gs.mm.imsi",      // 5G NAS IMSI on newer Wireshark versions
	"nas_eps.emm.imsi",     // LTE NAS IMSI on newer Wireshark versions
	"pfcp.user_id",         // PFCP User ID on newer Wireshark versions
	"pfcp.user_id.supi",    // PFCP User ID SUPI on newer Wireshark versions
	"e212.mcc",             // Needed to reconstruct IMSI from NAS-5GS SUCI MSIN
	"e212.mnc",             // Needed to reconstruct IMSI from NAS-5GS SUCI MSIN
	"nas_5gs.mm.suci.msin", // SUCI NULL-scheme MSIN, used when PFCP/IMSI fields are absent
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
	primarySet := make(map[string]bool)
	fallbackSet := make(map[string]bool)

	// Run both strategies in parallel
	var wg sync.WaitGroup
	wg.Add(2)

	// Strategy 1: Fast field extraction (single tshark call)
	go func() {
		defer wg.Done()
		results := s.scanByFieldsFast(ctx, pcapFile)
		mu.Lock()
		mergeBoolSet(primarySet, results.primary)
		mergeBoolSet(fallbackSet, results.fallback)
		mu.Unlock()
	}()

	// Strategy 2: Verbose scan with combined filter (single tshark call)
	go func() {
		defer wg.Done()
		results := s.scanVerboseCombined(ctx, pcapFile)
		mu.Lock()
		for imsi := range results {
			primarySet[imsi] = true
		}
		mu.Unlock()
	}()

	wg.Wait()

	return sortedIMSISet(preferredIMSISet(primarySet, fallbackSet)), nil
}

// scanByFieldsFast extracts IMSI using a single tshark call with all known fields
func (s *IMSIScanner) scanByFieldsFast(ctx context.Context, pcapFile string) imsiFieldBuckets {
	buckets := newIMSIFieldBuckets()
	log.Printf("[IMSIScanner] scanByFieldsFast starting, pcapFile: %s", pcapFile)

	fields := supportedIMSIFields(ctx)
	if len(fields) == 0 {
		return buckets
	}

	// Single tshark call with combined filter for signaling protocols
	filter := imsiFieldScanFilter()
	log.Printf("[IMSIScanner] scanByFieldsFast tshark filter: %s", filter)
	log.Printf("[IMSIScanner] scanByFieldsFast tshark fields: %v", fields)

	result, err := tshark.TsharkFields(ctx, pcapFile, filter, fields)
	if err != nil {
		log.Printf("[IMSIScanner] scanByFieldsFast tshark error: %v", err)
		return buckets
	}

	log.Printf("[IMSIScanner] scanByFieldsFast tshark exitCode: %d, stderr: %s", result.ExitCode, result.Stderr)
	if result.ExitCode != 0 {
		log.Printf("[IMSIScanner] scanByFieldsFast tshark non-zero exit code")
	}

	// Parse field output efficiently
	lines := strings.Split(result.Stdout, "\n")
	log.Printf("[IMSIScanner] scanByFieldsFast got %d lines of output", len(lines))

	buckets = s.extractIMSIsFromFieldLines(fields, lines)

	log.Printf("[IMSIScanner] scanByFieldsFast found %d primary IMSIs, %d SUCI fallback IMSIs",
		len(buckets.primary), len(buckets.fallback))
	return buckets
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

// ScanIMSIsStream scans IMSI values and streams results through a channel.
// It waits until both scan strategies finish so SUCI MSIN fallback values are only emitted
// when no primary IMSI source (PFCP/direct IMSI fields or verbose IMSI text) was found.
func (s *IMSIScanner) ScanIMSIsStream(ctx context.Context, pcapFile string, imsiChan chan<- string) error {
	defer close(imsiChan)

	var mu sync.Mutex
	primarySet := make(map[string]bool)
	fallbackSet := make(map[string]bool)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		results := s.scanByFieldsFast(ctx, pcapFile)
		mu.Lock()
		mergeBoolSet(primarySet, results.primary)
		mergeBoolSet(fallbackSet, results.fallback)
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		results := s.scanVerboseCombined(ctx, pcapFile)
		mu.Lock()
		for imsi := range results {
			primarySet[imsi] = true
		}
		mu.Unlock()
	}()

	wg.Wait()

	for _, imsi := range sortedIMSISet(preferredIMSISet(primarySet, fallbackSet)) {
		select {
		case imsiChan <- imsi:
		case <-ctx.Done():
			return nil
		}
	}
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

	filter := imsiFieldScanFilter()
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
	buckets := s.extractIMSIsFromFieldLines(fields, lines)
	for _, imsi := range sortedIMSISet(preferredIMSISet(buckets.primary, buckets.fallback)) {
		foundCount++
		sendIMSI(imsi)
	}
	log.Printf("[IMSIScanner] scanByFieldsStream completed, found %d IMSIs", foundCount)
}

type imsiFieldBuckets struct {
	primary  map[string]bool
	fallback map[string]bool
}

func newIMSIFieldBuckets() imsiFieldBuckets {
	return imsiFieldBuckets{
		primary:  make(map[string]bool),
		fallback: make(map[string]bool),
	}
}

func (s *IMSIScanner) extractIMSIsFromFieldLines(fields []string, lines []string) imsiFieldBuckets {
	buckets := newIMSIFieldBuckets()
	for _, line := range lines {
		if line == "" {
			continue
		}
		lineBuckets := s.extractIMSIBucketsFromFieldLine(fields, line)
		mergeBoolSet(buckets.primary, lineBuckets.primary)
		mergeBoolSet(buckets.fallback, lineBuckets.fallback)
	}
	return buckets
}

func (s *IMSIScanner) extractIMSIsFromFieldLine(fields []string, line string) []string {
	buckets := s.extractIMSIBucketsFromFieldLine(fields, line)
	return sortedIMSISet(preferredIMSISet(buckets.primary, buckets.fallback))
}

func (s *IMSIScanner) extractIMSIBucketsFromFieldLine(fields []string, line string) imsiFieldBuckets {
	cols := strings.Split(line, "\t")
	buckets := newIMSIFieldBuckets()
	var mccValues []string
	var mncValues []string
	var msinValues []string

	for idx, field := range fields {
		if idx >= len(cols) {
			break
		}

		values := splitTsharkValues(cols[idx])
		if isDirectIMSIField(field) {
			for _, value := range values {
				for _, imsi := range s.extractValidIMSIsFromValue(value) {
					buckets.primary[imsi] = true
				}
			}
		}

		switch field {
		case "e212.mcc":
			mccValues = append(mccValues, values...)
		case "e212.mnc":
			mncValues = append(mncValues, values...)
		case "nas_5gs.mm.suci.msin":
			msinValues = append(msinValues, values...)
		}
	}

	for _, mcc := range mccValues {
		mcc = normalizeDecimalDigits(mcc, 3, 3)
		if mcc == "" {
			continue
		}
		for _, mnc := range mncValues {
			for _, msin := range msinValues {
				if imsi := buildIMSIFromSUCIMSIN(mcc, mnc, msin); s.isValidIMSI(imsi) {
					buckets.fallback[imsi] = true
				}
			}
		}
	}

	return buckets
}

func isDirectIMSIField(field string) bool {
	switch field {
	case "e212.imsi", "gsm_a.imsi", "nas_5gs.mm.imsi", "nas_eps.emm.imsi", "pfcp.user_id", "pfcp.user_id.supi":
		return true
	default:
		return false
	}
}

func (s *IMSIScanner) extractValidIMSIsFromValue(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	imsiSet := make(map[string]bool)
	for _, valuePart := range splitTsharkValues(value) {
		if s.isValidIMSI(valuePart) {
			imsiSet[valuePart] = true
			continue
		}
		for _, match := range s.imsiPattern.FindAllStringSubmatch(valuePart, -1) {
			if len(match) > 1 && s.isValidIMSI(match[1]) {
				imsiSet[match[1]] = true
			}
		}
	}
	return sortedIMSISet(imsiSet)
}

func buildIMSIFromSUCIMSIN(mcc, mnc, msin string) string {
	msin = normalizeDecimalDigits(msin, 9, 10)
	if msin == "" {
		return ""
	}

	mnc = strings.TrimSpace(mnc)
	mnc = strings.Trim(mnc, `"`)
	if mnc == "" {
		return ""
	}
	for _, c := range mnc {
		if c < '0' || c > '9' {
			return ""
		}
	}

	if len(mnc) == 1 {
		mnc = "0" + mnc
	}
	if len(mnc) < 2 || len(mnc) > 3 {
		return ""
	}

	return mcc + mnc + msin
}

func normalizeDecimalDigits(value string, minLen, maxLen int) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	if value == "" {
		return ""
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return ""
		}
	}
	if len(value) < minLen || len(value) > maxLen {
		return ""
	}
	return value
}

func preferredIMSISet(primary, fallback map[string]bool) map[string]bool {
	if len(primary) > 0 {
		return primary
	}
	return fallback
}

func sortedIMSISet(imsiSet map[string]bool) []string {
	imsiList := make([]string, 0, len(imsiSet))
	for imsi := range imsiSet {
		imsiList = append(imsiList, imsi)
	}
	sort.Strings(imsiList)
	return imsiList
}

func mergeBoolSet(dst, src map[string]bool) {
	for value := range src {
		dst[value] = true
	}
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

func imsiFieldScanFilter() string {
	return "gtpv2 or s1ap or ngap or nas-5gs or diameter or pfcp"
}
