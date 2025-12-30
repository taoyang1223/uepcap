package protocol

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

// FilterResolver resolves display filters for IMSI + protocols
type FilterResolver struct {
	ngapResolver  *NGAPResolver
	pfcpResolver  *PFCPResolver
	s1apResolver  *S1APResolver
	gtpv2Resolver *GTPv2Resolver
	ueipResolver  *UEIPResolver
	sbiResolver   *SBIResolver
}

// NewFilterResolver creates a new filter resolver
func NewFilterResolver() *FilterResolver {
	ngap := NewNGAPResolver()
	s1ap := NewS1APResolver()
	pfcp := NewPFCPResolver()
	// Inject PFCP resolver into NGAP resolver for TEID-based primary resolution
	ngap.SetPFCPResolver(pfcp)
	return &FilterResolver{
		ngapResolver:  ngap,
		pfcpResolver:  pfcp,
		s1apResolver:  s1ap,
		gtpv2Resolver: NewGTPv2Resolver(),
		ueipResolver:  NewUEIPResolver(ngap, s1ap),
		sbiResolver:   NewSBIResolver(),
	}
}

// ResolveFilters resolves per-protocol display filters for an IMSI.
// It returns:
// - filtersByProto: map[proto]filter (proto is normalized to lower-case)
// - combinedFilter: OR-combined filter across all non-empty protocol filters
//
// Notes:
// - Resolvers run in parallel for performance.
// - Errors from individual protocols are ignored (best-effort), consistent with ResolveFilter.
func (r *FilterResolver) ResolveFilters(ctx context.Context, pcapFile, imsi string, protocols []string) (filtersByProto map[string]string, combinedFilter string, err error) {
	type filterResult struct {
		protoKey string
		filter   string
		err      error
	}

	resultChan := make(chan filterResult, len(protocols))
	var wg sync.WaitGroup

	for _, proto := range protocols {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			protoKey := strings.ToLower(p)
			var filter string
			var callErr error

			switch protoKey {
			case "ngap":
				filter, callErr = r.ngapResolver.ResolveFilter(ctx, pcapFile, imsi)
			case "pfcp":
				filter, callErr = r.pfcpResolver.ResolveFilter(ctx, pcapFile, imsi)
			case "s1ap":
				filter, callErr = r.s1apResolver.ResolveFilter(ctx, pcapFile, imsi)
			case "gtpv2":
				filter, callErr = r.gtpv2Resolver.ResolveFilter(ctx, pcapFile, imsi)
			case "gtpu":
				filter, callErr = r.gtpv2Resolver.ResolveGTPUFilter(ctx, pcapFile, imsi)
			case "ueip":
				filter, callErr = r.ueipResolver.ResolveFilter(ctx, pcapFile, imsi)
			case "sbi":
				filter, callErr = r.sbiResolver.ResolveFilter(ctx, pcapFile, imsi)
			default:
				return
			}

			resultChan <- filterResult{protoKey: protoKey, filter: filter, err: callErr}
		}(proto)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	filtersByProto = make(map[string]string, len(protocols))
	var filters []string
	for result := range resultChan {
		if result.err != nil {
			continue
		}
		if result.filter == "" {
			continue
		}
		filtersByProto[result.protoKey] = result.filter
		filters = append(filters, "("+result.filter+")")
	}

	if len(filters) == 0 {
		return filtersByProto, "", nil
	}

	return filtersByProto, strings.Join(filters, " || "), nil
}

// ResolveFilter resolves a combined display filter for an IMSI across multiple protocols
// Optimized: processes protocols in parallel for better performance
func (r *FilterResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string, protocols []string) (string, error) {
	_, combined, err := r.ResolveFilters(ctx, pcapFile, imsi, protocols)
	return combined, err
}

// NGAPResolver resolves NGAP filters for an IMSI
type NGAPResolver struct {
	pfcpResolver *PFCPResolver // Used for PFCP→TEID primary resolution path
}

// NewNGAPResolver creates a new NGAP resolver
func NewNGAPResolver() *NGAPResolver {
	return &NGAPResolver{}
}

// SetPFCPResolver injects the PFCP resolver for TEID-based NGAP resolution
func (r *NGAPResolver) SetPFCPResolver(pfcp *PFCPResolver) {
	r.pfcpResolver = pfcp
}

// ResolveFilter resolves NGAP display filter for an IMSI
// Uses a primary-backup strategy:
// - Primary: PFCP→TEID→NGAP(procedureCode=29)→RAN_UE_NGAP_ID→5G-TMSI expansion
// - Backup: MSIN-based InitialUEMessage matching (existing approach)
func (r *NGAPResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Try primary path first: PFCP→TEID→NGAP(29)→RANID
	if r.pfcpResolver != nil {
		filter, err := r.resolveByPfcpTeid(ctx, pcapFile, imsi)
		if err == nil && filter != "" {
			return filter, nil
		}
		// Primary path failed or returned empty, fall through to backup
	}

	// Backup path: MSIN-based approach (existing logic)
	return r.resolveByMSIN(ctx, pcapFile, imsi)
}

// normalize5GTMSIToDecimal converts a 5G-TMSI string (hex like 0x1234 or decimal like 305419896)
// to a decimal string suitable for Wireshark/tshark display filter.
//
// Note: field names vary by dissector/version; `nas_5gs.5g_tmsi` does NOT exist on some
// tshark builds. We use the generic `3gpp.tmsi` field (TMSI/P-TMSI/M-TMSI/5G-TMSI) for compatibility.
func normalize5GTMSIToDecimal(tmsi string) (string, bool) {
	tmsi = strings.TrimSpace(tmsi)
	if tmsi == "" {
		return "", false
	}
	var val uint64
	var err error
	if strings.HasPrefix(tmsi, "0x") || strings.HasPrefix(tmsi, "0X") {
		val, err = strconv.ParseUint(tmsi[2:], 16, 32)
	} else {
		val, err = strconv.ParseUint(tmsi, 10, 32)
	}
	if err != nil {
		return "", false
	}
	return strconv.FormatUint(val, 10), true
}

// expandRanIDsBy5GTMSI iteratively expands RAN_UE_NGAP_IDs using discovered 5G-TMSIs:
// - Start with seed RAN IDs
// - Extract 5G-TMSIs from context for current RAN/AMF IDs
// - Use those 5G-TMSIs to find more RAN IDs from InitialUEMessage output
// Repeat until no new RAN IDs / TMSIs (or max iterations).
func (r *NGAPResolver) expandRanIDsBy5GTMSI(ctx context.Context, pcapFile string, initialUEOutput string, seedRanIDs []string) (ranIDs []string, amfIDs []string, fiveGTMSIs []string) {
	ranSet := make(map[string]bool)
	for _, rid := range seedRanIDs {
		if rid != "" {
			ranSet[rid] = true
		}
	}
	tmsiSet := make(map[string]bool)

	const maxIters = 5
	for iter := 0; iter < maxIters; iter++ {
		// Snapshot current RAN IDs
		var currentRanIDs []string
		for rid := range ranSet {
			currentRanIDs = append(currentRanIDs, rid)
		}
		if len(currentRanIDs) == 0 {
			break
		}

		// Find AMF IDs for current RAN IDs
		currentAMFIDs := r.findAMFIDsForRanIDs(ctx, pcapFile, currentRanIDs)

		// Extract 5G-TMSIs from context of current IDs
		newTMSIs := r.extract5GTMSIsFromContext(ctx, pcapFile, currentRanIDs, currentAMFIDs)
		anyNewTMSI := false
		for _, t := range newTMSIs {
			if t == "" || t == "0x00000000" || t == "0" {
				continue
			}
			if !tmsiSet[t] {
				tmsiSet[t] = true
				anyNewTMSI = true
			}
		}

		// Expand RAN IDs using all known TMSIs
		anyNewRan := false
		if initialUEOutput != "" && len(tmsiSet) > 0 {
			var allTMSIs []string
			for t := range tmsiSet {
				allTMSIs = append(allTMSIs, t)
			}
			additionalRanIDs := r.findRanIDsBy5GTMSI(initialUEOutput, allTMSIs)
			for _, rid := range additionalRanIDs {
				if rid == "" {
					continue
				}
				if !ranSet[rid] {
					ranSet[rid] = true
					anyNewRan = true
				}
			}
		}

		if !anyNewRan && !anyNewTMSI {
			break
		}
	}

	for rid := range ranSet {
		ranIDs = append(ranIDs, rid)
	}

	amfIDs = r.findAMFIDsForRanIDs(ctx, pcapFile, ranIDs)

	for t := range tmsiSet {
		fiveGTMSIs = append(fiveGTMSIs, t)
	}
	return ranIDs, amfIDs, fiveGTMSIs
}

// resolveByPfcpTeid implements the primary NGAP resolution path:
// 1. Get TEIDs from PFCP Session Establishment Response (msg_type=51)
// 2. Use ngap.gTP_TEID + procedureCode=29 to find seed RAN_UE_NGAP_IDs
// 3. From InitialUEMessage (procedureCode=15), extract 5G-TMSIs for seed RAN IDs
// 4. Use 5G-TMSIs to expand and find all related RAN_UE_NGAP_IDs
// 5. Find associated AMF_UE_NGAP_IDs and build the final filter
func (r *NGAPResolver) resolveByPfcpTeid(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Step 1: Get TEIDs from PFCP
	teids, err := r.pfcpResolver.ResolveSessionTEIDs(ctx, pcapFile, imsi)
	if err != nil || len(teids) == 0 {
		return "", err
	}

	// Step 2: Build filter for NGAP procedureCode=29 with matching gTP_TEID
	// Convert TEIDs to ngap.gTP_TEID format (xx:xx:xx:xx)
	var teidFilters []string
	for _, teid := range teids {
		teidBytes, ok := teidToNgapBytes(teid)
		if !ok {
			continue
		}
		teidFilters = append(teidFilters, fmt.Sprintf("(ngap.gTP_TEID == %s && ngap.procedureCode == 29)", teidBytes))
	}

	if len(teidFilters) == 0 {
		return "", nil
	}

	// Query NGAP with TEID filter to get seed RAN IDs
	ngapTeidFilter := strings.Join(teidFilters, " || ")
	ngap29Result, err := tshark.TsharkVerbose(ctx, pcapFile, ngapTeidFilter)
	if err != nil {
		return "", err
	}

	seedRanIDs := r.extractRanIDsFromNGAPVerbose(ngap29Result.Stdout)
	if len(seedRanIDs) == 0 {
		return "", nil
	}

	// Step 3: Get InitialUEMessage output for 5G-TMSI extraction
	initialUEResult, err := tshark.TsharkVerbose(ctx, pcapFile, "ngap.procedureCode == 15")
	initialUEOutput := ""
	if err == nil {
		initialUEOutput = initialUEResult.Stdout
	}

	// Step 4/5: Iteratively expand by 5G-TMSI
	ranIDs, allAMFIDs, fiveGTMSIs := r.expandRanIDsBy5GTMSI(ctx, pcapFile, initialUEOutput, seedRanIDs)

	// Build filter
	var parts []string
	for _, amfID := range allAMFIDs {
		parts = append(parts, fmt.Sprintf("ngap.AMF_UE_NGAP_ID == %s", amfID))
	}
	for _, ranID := range ranIDs {
		parts = append(parts, fmt.Sprintf("ngap.RAN_UE_NGAP_ID == %s", ranID))
	}
	// Also include 5G-TMSI filters (decimal form).
	// Use the generic 3GPP TMSI field for better compatibility across tshark versions.
	tmsiDecSet := make(map[string]bool)
	for _, t := range fiveGTMSIs {
		dec, ok := normalize5GTMSIToDecimal(t)
		if !ok || dec == "0" {
			continue
		}
		if !tmsiDecSet[dec] {
			tmsiDecSet[dec] = true
			parts = append(parts, fmt.Sprintf("3gpp.tmsi == %s", dec))
		}
	}

	if len(parts) == 0 {
		return "", nil
	}

	return strings.Join(parts, " || "), nil
}

// resolveByMSIN implements the backup NGAP resolution path (original MSIN-based approach)
func (r *NGAPResolver) resolveByMSIN(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Step 1: Find RAN-UE-NGAP-ID from InitialUEMessage containing MSIN (initial registration)
	msin := getMSIN(imsi)

	// Search InitialUEMessage for MSIN (multiple registrations = multiple RAN_UE_NGAP_IDs)
	result, err := tshark.TsharkVerbose(ctx, pcapFile, "ngap.procedureCode == 15")
	if err != nil {
		return "", err
	}

	seedRanIDs := r.extractRanIDsFromInitialUE(result.Stdout, msin)

	if len(seedRanIDs) == 0 {
		return "", nil
	}

	// Step 2+: Iteratively expand by 5G-TMSI using InitialUEMessage output
	ranIDs, amfIDs, fiveGTMSIs := r.expandRanIDsBy5GTMSI(ctx, pcapFile, result.Stdout, seedRanIDs)

	// Build filter using both RAN_UE_NGAP_ID and AMF_UE_NGAP_ID
	// For accurate filtering, we should use (RAN_ID && AMF_ID) pairs when both are available
	var parts []string

	// If we have AMF IDs, they are more reliable for filtering as they persist across procedures
	for _, amfID := range amfIDs {
		parts = append(parts, fmt.Sprintf("ngap.AMF_UE_NGAP_ID == %s", amfID))
	}

	// Also add RAN IDs for messages that don't have AMF ID yet (early registration)
	for _, ranID := range ranIDs {
		parts = append(parts, fmt.Sprintf("ngap.RAN_UE_NGAP_ID == %s", ranID))
	}

	// Also include 5G-TMSI filters (decimal form).
	// Use the generic 3GPP TMSI field for better compatibility across tshark versions.
	tmsiDecSet := make(map[string]bool)
	for _, t := range fiveGTMSIs {
		dec, ok := normalize5GTMSIToDecimal(t)
		if !ok || dec == "0" {
			continue
		}
		if !tmsiDecSet[dec] {
			tmsiDecSet[dec] = true
			parts = append(parts, fmt.Sprintf("3gpp.tmsi == %s", dec))
		}
	}

	return strings.Join(parts, " || "), nil
}

// extractRanIDsFromNGAPVerbose extracts RAN_UE_NGAP_IDs from NGAP verbose output
// This is used for extracting RAN IDs from procedureCode=29 (PDUSessionResourceSetup) messages
func (r *NGAPResolver) extractRanIDsFromNGAPVerbose(output string) []string {
	ranIDSet := make(map[string]bool)

	ranPattern := regexp.MustCompile(`RAN-UE-NGAP-ID:\s*(\d+)`)
	matches := ranPattern.FindAllStringSubmatch(output, -1)
	for _, match := range matches {
		if len(match) > 1 {
			ranIDSet[match[1]] = true
		}
	}

	var ranIDs []string
	for id := range ranIDSet {
		ranIDs = append(ranIDs, id)
	}
	return ranIDs
}

// extractRanIDsFromInitialUE extracts RAN_UE_NGAP_IDs from InitialUEMessage output for a specific MSIN
// Supports multiple RAN IDs (multiple registrations from the same UE)
func (r *NGAPResolver) extractRanIDsFromInitialUE(output, msin string) []string {
	ranIDSet := make(map[string]bool)

	// Parse output to find frames with MSIN and extract RAN IDs
	lines := strings.Split(output, "\n")
	var currentRanID string
	var foundMSIN bool

	ranPattern := regexp.MustCompile(`RAN-UE-NGAP-ID:\s*(\d+)`)
	msinPattern := regexp.MustCompile(`MSIN:\s*(\d+)`)
	framePattern := regexp.MustCompile(`^Frame \d+:`)

	for _, line := range lines {
		if framePattern.MatchString(line) {
			// New frame, check if previous frame had our MSIN
			if foundMSIN && currentRanID != "" {
				ranIDSet[currentRanID] = true
			}
			currentRanID = ""
			foundMSIN = false
		}

		if match := ranPattern.FindStringSubmatch(line); len(match) > 1 {
			currentRanID = match[1]
		}
		if match := msinPattern.FindStringSubmatch(line); len(match) > 1 {
			if match[1] == msin {
				foundMSIN = true
			}
		}
	}

	// Check last frame
	if foundMSIN && currentRanID != "" {
		ranIDSet[currentRanID] = true
	}

	var ranIDs []string
	for id := range ranIDSet {
		ranIDs = append(ranIDs, id)
	}
	return ranIDs
}

// findAMFIDsForRanIDs searches for AMF_UE_NGAP_IDs associated with given RAN_UE_NGAP_IDs
// AMF assigns AMF_UE_NGAP_ID in subsequent messages (e.g., InitialContextSetupRequest)
func (r *NGAPResolver) findAMFIDsForRanIDs(ctx context.Context, pcapFile string, ranIDs []string) []string {
	amfIDSet := make(map[string]bool)
	amfPattern := regexp.MustCompile(`AMF-UE-NGAP-ID:\s*(\d+)`)

	// For each RAN_UE_NGAP_ID, find associated AMF_UE_NGAP_IDs
	// Process in parallel for better performance
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ranID := range ranIDs {
		wg.Add(1)
		go func(rid string) {
			defer wg.Done()

			// Search for messages with this RAN_UE_NGAP_ID
			result, err := tshark.TsharkVerbose(ctx, pcapFile, fmt.Sprintf("ngap.RAN_UE_NGAP_ID == %s", rid))
			if err != nil {
				return
			}

			// Extract all AMF_UE_NGAP_IDs from matched messages
			matches := amfPattern.FindAllStringSubmatch(result.Stdout, -1)
			mu.Lock()
			for _, match := range matches {
				if len(match) > 1 {
					amfIDSet[match[1]] = true
				}
			}
			mu.Unlock()
		}(ranID)
	}

	wg.Wait()

	var amfIDs []string
	for id := range amfIDSet {
		amfIDs = append(amfIDs, id)
	}
	return amfIDs
}

// extract5GTMSIsFromContext extracts 5G-TMSI values allocated to the UE from RegistrationAccept
// The 5G-TMSI is assigned by AMF and included in 5G-GUTI IE of Registration Accept message
// This is used to track subsequent registrations using 5G-GUTI (periodic/mobility/emergency)
func (r *NGAPResolver) extract5GTMSIsFromContext(ctx context.Context, pcapFile string, ranIDs, amfIDs []string) []string {
	tmsiSet := make(map[string]bool)

	// Build filter for UE context messages (DownlinkNASTransport containing RegistrationAccept)
	// RegistrationAccept is NAS message, transmitted via NGAP DownlinkNASTransport
	var filterParts []string
	for _, amfID := range amfIDs {
		filterParts = append(filterParts, fmt.Sprintf("ngap.AMF_UE_NGAP_ID == %s", amfID))
	}
	for _, ranID := range ranIDs {
		filterParts = append(filterParts, fmt.Sprintf("ngap.RAN_UE_NGAP_ID == %s", ranID))
	}

	if len(filterParts) == 0 {
		return nil
	}

	filter := strings.Join(filterParts, " || ")
	result, err := tshark.TsharkVerbose(ctx, pcapFile, filter)
	if err != nil {
		return nil
	}

	// Extract 5G-TMSI from verbose output
	// Look for patterns like:
	// - "5G-TMSI: 0xXXXXXXXX" or "5G-TMSI: NNNNNNNN"
	// - "fiveG-TMSI: 0xXXXXXXXX"
	// These appear in RegistrationAccept NAS message within 5G-GUTI IE
	tmsiPatterns := []*regexp.Regexp{
		regexp.MustCompile(`5G-TMSI:\s*(0x[0-9a-fA-F]+|\d+)`),
		regexp.MustCompile(`fiveG-TMSI:\s*(0x[0-9a-fA-F]+|\d+)`),
		regexp.MustCompile(`5G-S-TMSI.*?5G-TMSI:\s*(0x[0-9a-fA-F]+|\d+)`),
	}

	lines := strings.Split(result.Stdout, "\n")
	for _, line := range lines {
		for _, pattern := range tmsiPatterns {
			if match := pattern.FindStringSubmatch(line); len(match) > 1 {
				tmsi := match[1]
				// Normalize to consistent format
				if strings.HasPrefix(tmsi, "0x") {
					tmsiSet[tmsi] = true
				} else {
					// Convert decimal to hex for consistency
					tmsiSet[tmsi] = true
				}
			}
		}
	}

	var tmsiList []string
	for tmsi := range tmsiSet {
		tmsiList = append(tmsiList, tmsi)
	}
	return tmsiList
}

// findRanIDsBy5GTMSI finds RAN_UE_NGAP_IDs from InitialUEMessage containing matching 5G-S-TMSI
// This is used to capture periodic/mobility/emergency registrations using 5G-GUTI
// When UE uses 5G-GUTI for registration, InitialUEMessage contains 5G-S-TMSI (not SUCI/MSIN)
func (r *NGAPResolver) findRanIDsBy5GTMSI(initialUEOutput string, fiveGTMSIs []string) []string {
	ranIDSet := make(map[string]bool)

	// Build TMSI lookup set (normalize values)
	tmsiLookup := make(map[string]bool)
	for _, tmsi := range fiveGTMSIs {
		// Store both original and normalized forms
		tmsiLookup[tmsi] = true
		// Also store without 0x prefix if hex
		if strings.HasPrefix(tmsi, "0x") {
			tmsiLookup[strings.TrimPrefix(tmsi, "0x")] = true
			tmsiLookup[strings.ToLower(strings.TrimPrefix(tmsi, "0x"))] = true
			tmsiLookup[strings.ToUpper(strings.TrimPrefix(tmsi, "0x"))] = true
		}
	}

	ranPattern := regexp.MustCompile(`RAN-UE-NGAP-ID:\s*(\d+)`)
	// 5G-S-TMSI contains AMF Set ID + AMF Pointer + 5G-TMSI
	// We need to match the 5G-TMSI part
	tmsiInFramePattern := regexp.MustCompile(`5G-TMSI:\s*(0x[0-9a-fA-F]+|[0-9a-fA-F]+|\d+)`)
	framePattern := regexp.MustCompile(`^Frame \d+:`)

	lines := strings.Split(initialUEOutput, "\n")
	var currentRanID string
	var foundMatchingTMSI bool

	for _, line := range lines {
		if framePattern.MatchString(line) {
			// New frame, check if previous frame had our TMSI
			if foundMatchingTMSI && currentRanID != "" {
				ranIDSet[currentRanID] = true
			}
			currentRanID = ""
			foundMatchingTMSI = false
		}

		if match := ranPattern.FindStringSubmatch(line); len(match) > 1 {
			currentRanID = match[1]
		}

		if match := tmsiInFramePattern.FindStringSubmatch(line); len(match) > 1 {
			tmsiValue := match[1]
			// Check if this TMSI matches any of our known TMSIs
			if tmsiLookup[tmsiValue] {
				foundMatchingTMSI = true
			}
			// Also try normalized forms
			normalized := strings.TrimPrefix(strings.ToLower(tmsiValue), "0x")
			if tmsiLookup[normalized] {
				foundMatchingTMSI = true
			}
		}
	}

	// Check last frame
	if foundMatchingTMSI && currentRanID != "" {
		ranIDSet[currentRanID] = true
	}

	var ranIDs []string
	for id := range ranIDSet {
		ranIDs = append(ranIDs, id)
	}
	return ranIDs
}

// PFCPResolver resolves PFCP filters for an IMSI
type PFCPResolver struct{}

// NewPFCPResolver creates a new PFCP resolver
func NewPFCPResolver() *PFCPResolver {
	return &PFCPResolver{}
}

// ResolveFilter resolves PFCP display filter for an IMSI
// Logic:
// 1. Find IMSI in Session Establishment Request, extract SMF CP F-SEID from F-SEID IE
// 2. Find Response where pfcp.seid == SMF CP F-SEID, extract UP F-SEID from F-SEID IE
// 3. Build filter using both SEIDs
func (r *PFCPResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Step 1: Scan Session Establishment Request (msg_type=50) for IMSI
	// Extract SMF CP F-SEID from F-SEID IE
	reqResult, err := tshark.TsharkVerbose(ctx, pcapFile, "pfcp.msg_type == 50")
	if err != nil {
		return "", err
	}

	smfSEIDs := r.extractSMFSEIDsFromRequest(reqResult.Stdout, imsi)
	if len(smfSEIDs) == 0 {
		return "", nil
	}

	// Collect all SEIDs
	seidSet := make(map[string]bool)
	for _, seid := range smfSEIDs {
		seidSet[seid] = true
	}

	// Step 2: Scan Session Establishment Response (msg_type=51)
	// Find Response where pfcp.seid matches SMF CP F-SEID, extract UP F-SEID
	respResult, err := tshark.TsharkVerbose(ctx, pcapFile, "pfcp.msg_type == 51")
	if err == nil {
		upSEIDs := r.extractUPSEIDsFromResponse(respResult.Stdout, smfSEIDs)
		for _, seid := range upSEIDs {
			seidSet[seid] = true
		}
	}

	// Build filter: include IMSI filter + SEID filters
	var parts []string

	// Add IMSI filter to capture original messages containing the IMSI
	// Use e212.imsi with pfcp protocol filter (pfcp doesn't have dedicated imsi field)
	parts = append(parts, fmt.Sprintf("(pfcp && e212.imsi == \"%s\")", imsi))

	// Add SEID filters
	for seid := range seidSet {
		parts = append(parts, fmt.Sprintf("pfcp.seid == %s", seid))
	}

	return strings.Join(parts, " || "), nil
}

// extractSMFSEIDsFromRequest extracts SMF CP F-SEID from F-SEID IE in Request messages containing IMSI
func (r *PFCPResolver) extractSMFSEIDsFromRequest(output, imsi string) []string {
	seidSet := make(map[string]bool)

	lines := strings.Split(output, "\n")
	var currentFSEID string
	var foundIMSI bool
	var inFSEIDIE bool

	// Pattern to match F-SEID IE section
	fseidIEPattern := regexp.MustCompile(`F-SEID`)
	// Pattern to match SEID value inside F-SEID IE
	seidValuePattern := regexp.MustCompile(`SEID:\s*(0x[0-9a-fA-F]+|\d+)`)
	// Pattern to match IMSI
	imsiPattern := regexp.MustCompile(`IMSI:\s*` + regexp.QuoteMeta(imsi))
	framePattern := regexp.MustCompile(`^Frame \d+:`)

	for _, line := range lines {
		if framePattern.MatchString(line) {
			// New frame, save previous if it had our IMSI
			if foundIMSI && currentFSEID != "" {
				seidSet[currentFSEID] = true
			}
			currentFSEID = ""
			foundIMSI = false
			inFSEIDIE = false
		}

		// Detect F-SEID IE section
		if fseidIEPattern.MatchString(line) {
			inFSEIDIE = true
		}

		// Extract SEID value from F-SEID IE (only the first one per frame, which is SMF's)
		if inFSEIDIE && currentFSEID == "" {
			if match := seidValuePattern.FindStringSubmatch(line); len(match) > 1 {
				// Skip zero SEID
				if match[1] != "0x0000000000000000" && match[1] != "0" {
					currentFSEID = match[1]
					inFSEIDIE = false
				}
			}
		}

		if imsiPattern.MatchString(line) {
			foundIMSI = true
		}
	}

	// Check last frame
	if foundIMSI && currentFSEID != "" {
		seidSet[currentFSEID] = true
	}

	var seids []string
	for seid := range seidSet {
		seids = append(seids, seid)
	}
	return seids
}

// extractUPSEIDsFromResponse extracts UP F-SEID from Response messages
// where pfcp.seid (header) matches one of the SMF SEIDs
func (r *PFCPResolver) extractUPSEIDsFromResponse(output string, smfSEIDs []string) []string {
	// Build lookup set for SMF SEIDs
	smfSEIDSet := make(map[string]bool)
	for _, seid := range smfSEIDs {
		smfSEIDSet[seid] = true
	}

	seidSet := make(map[string]bool)

	lines := strings.Split(output, "\n")
	var headerSEID string
	var fseidInIE string
	var inFSEIDIE bool

	// Pattern to match header SEID (pfcp.seid)
	headerSEIDPattern := regexp.MustCompile(`SEID:\s*(0x[0-9a-fA-F]+|\d+)`)
	// Pattern to match F-SEID IE section
	fseidIEPattern := regexp.MustCompile(`F-SEID`)
	framePattern := regexp.MustCompile(`^Frame \d+:`)

	for _, line := range lines {
		if framePattern.MatchString(line) {
			// New frame, check if previous frame's header SEID matches SMF SEID
			if headerSEID != "" && smfSEIDSet[headerSEID] && fseidInIE != "" {
				seidSet[fseidInIE] = true
			}
			headerSEID = ""
			fseidInIE = ""
			inFSEIDIE = false
		}

		// First SEID in frame is the header SEID (pfcp.seid)
		if headerSEID == "" {
			if match := headerSEIDPattern.FindStringSubmatch(line); len(match) > 1 {
				headerSEID = match[1]
				continue
			}
		}

		// Detect F-SEID IE section
		if fseidIEPattern.MatchString(line) {
			inFSEIDIE = true
		}

		// Extract SEID value from F-SEID IE (UP F-SEID)
		if inFSEIDIE && fseidInIE == "" {
			if match := headerSEIDPattern.FindStringSubmatch(line); len(match) > 1 {
				if match[1] != "0x0000000000000000" && match[1] != "0" {
					fseidInIE = match[1]
					inFSEIDIE = false
				}
			}
		}
	}

	// Check last frame
	if headerSEID != "" && smfSEIDSet[headerSEID] && fseidInIE != "" {
		seidSet[fseidInIE] = true
	}

	var seids []string
	for seid := range seidSet {
		seids = append(seids, seid)
	}
	return seids
}

// ResolveSessionTEIDs extracts TEIDs from PFCP Session Establishment Response (msg_type=51)
// for a given IMSI. This is used by NGAPResolver to correlate NGAP messages via gTP_TEID.
// Returns TEIDs from F-TEID IE in responses where the header SEID matches a session for this IMSI.
func (r *PFCPResolver) ResolveSessionTEIDs(ctx context.Context, pcapFile, imsi string) ([]string, error) {
	// Step 1: Get SMF SEIDs from Request (msg_type=50) for this IMSI
	reqResult, err := tshark.TsharkVerbose(ctx, pcapFile, "pfcp.msg_type == 50")
	if err != nil {
		return nil, err
	}

	smfSEIDs := r.extractSMFSEIDsFromRequest(reqResult.Stdout, imsi)
	if len(smfSEIDs) == 0 {
		return nil, nil
	}

	// Step 2: From Response (msg_type=51), extract TEIDs from F-TEID IE
	// where the header SEID matches one of the SMF SEIDs
	respResult, err := tshark.TsharkVerbose(ctx, pcapFile, "pfcp.msg_type == 51")
	if err != nil {
		return nil, err
	}

	teids := r.extractTEIDsFromSessionEstResp(respResult.Stdout, smfSEIDs)
	return teids, nil
}

// extractTEIDsFromSessionEstResp extracts TEIDs from F-TEID IE in Session Establishment Response
// Only processes frames where the header pfcp.seid matches one of the smfSEIDs
func (r *PFCPResolver) extractTEIDsFromSessionEstResp(output string, smfSEIDs []string) []string {
	// Build lookup set for SMF SEIDs
	smfSEIDSet := make(map[string]bool)
	for _, seid := range smfSEIDs {
		smfSEIDSet[seid] = true
	}

	teidSet := make(map[string]bool)

	lines := strings.Split(output, "\n")
	var headerSEID string
	var inFTEIDIE bool
	var currentFrameTEIDs []string

	// Pattern to match header SEID (pfcp.seid) - first SEID in frame
	seidPattern := regexp.MustCompile(`SEID:\s*(0x[0-9a-fA-F]+|\d+)`)
	// Pattern to match F-TEID IE section (note: F-TEID is different from F-SEID)
	fteidIEPattern := regexp.MustCompile(`F-TEID`)
	// Pattern to match TEID value inside F-TEID IE
	teidValuePattern := regexp.MustCompile(`TEID:\s*(0x[0-9a-fA-F]+|\d+)`)
	framePattern := regexp.MustCompile(`^Frame \d+:`)

	for _, line := range lines {
		if framePattern.MatchString(line) {
			// New frame: if previous frame's header SEID matches SMF SEID, collect its TEIDs
			if headerSEID != "" && smfSEIDSet[headerSEID] {
				for _, teid := range currentFrameTEIDs {
					teidSet[teid] = true
				}
			}
			headerSEID = ""
			inFTEIDIE = false
			currentFrameTEIDs = nil
		}

		// First SEID in frame is the header SEID (pfcp.seid)
		if headerSEID == "" {
			if match := seidPattern.FindStringSubmatch(line); len(match) > 1 {
				headerSEID = match[1]
				continue
			}
		}

		// Detect F-TEID IE section
		if fteidIEPattern.MatchString(line) {
			inFTEIDIE = true
		}

		// Extract TEID value from F-TEID IE
		if inFTEIDIE {
			if match := teidValuePattern.FindStringSubmatch(line); len(match) > 1 {
				teid := match[1]
				// Skip zero TEID
				if teid != "0x00000000" && teid != "0" && teid != "0x0" {
					currentFrameTEIDs = append(currentFrameTEIDs, teid)
				}
				inFTEIDIE = false // Move to next F-TEID IE
			}
		}
	}

	// Check last frame
	if headerSEID != "" && smfSEIDSet[headerSEID] {
		for _, teid := range currentFrameTEIDs {
			teidSet[teid] = true
		}
	}

	var teids []string
	for teid := range teidSet {
		teids = append(teids, teid)
	}
	return teids
}

// S1APResolver resolves S1AP filters for an IMSI
type S1APResolver struct{}

// NewS1APResolver creates a new S1AP resolver
func NewS1APResolver() *S1APResolver {
	return &S1APResolver{}
}

// ResolveFilter resolves S1AP display filter for an IMSI
func (r *S1APResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Try direct field first
	result, err := tshark.TsharkFields(ctx, pcapFile, fmt.Sprintf("e212.imsi == \"%s\"", imsi),
		[]string{"s1ap.mme_ue_s1ap_id", "s1ap.enb_ue_s1ap_id"})
	if err != nil {
		return "", err
	}

	mmeIDs, enbIDs := r.extractS1APIDs(result.Stdout)

	// If direct field didn't work, try verbose scan
	if len(mmeIDs) == 0 && len(enbIDs) == 0 {
		verboseResult, err := tshark.TsharkVerbose(ctx, pcapFile, "s1ap")
		if err != nil {
			return "", err
		}
		mmeIDs, enbIDs = r.extractS1APIDsFromVerbose(verboseResult.Stdout, imsi)
	}

	if len(mmeIDs) == 0 && len(enbIDs) == 0 {
		return "", nil
	}

	var parts []string
	for _, id := range mmeIDs {
		parts = append(parts, fmt.Sprintf("s1ap.mme_ue_s1ap_id == %s", id))
	}
	for _, id := range enbIDs {
		parts = append(parts, fmt.Sprintf("s1ap.enb_ue_s1ap_id == %s", id))
	}

	return strings.Join(parts, " || "), nil
}

func (r *S1APResolver) extractS1APIDs(output string) (mmeIDs, enbIDs []string) {
	mmeSet := make(map[string]bool)
	enbSet := make(map[string]bool)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), "\t")
		if len(parts) >= 2 {
			if parts[0] != "" {
				mmeSet[parts[0]] = true
			}
			if parts[1] != "" {
				enbSet[parts[1]] = true
			}
		}
	}

	for id := range mmeSet {
		mmeIDs = append(mmeIDs, id)
	}
	for id := range enbSet {
		enbIDs = append(enbIDs, id)
	}
	return
}

func (r *S1APResolver) extractS1APIDsFromVerbose(output, imsi string) (mmeIDs, enbIDs []string) {
	mmeSet := make(map[string]bool)
	enbSet := make(map[string]bool)

	mmePattern := regexp.MustCompile(`MME-UE-S1AP-ID:\s*(\d+)`)
	enbPattern := regexp.MustCompile(`eNB-UE-S1AP-ID:\s*(\d+)`)
	imsiPattern := regexp.MustCompile(`IMSI:\s*` + regexp.QuoteMeta(imsi))

	lines := strings.Split(output, "\n")
	var foundIMSI bool
	var currentMME, currentENB string

	for _, line := range lines {
		if strings.HasPrefix(line, "Frame ") {
			if foundIMSI {
				if currentMME != "" {
					mmeSet[currentMME] = true
				}
				if currentENB != "" {
					enbSet[currentENB] = true
				}
			}
			foundIMSI = false
			currentMME = ""
			currentENB = ""
		}

		if match := mmePattern.FindStringSubmatch(line); len(match) > 1 {
			currentMME = match[1]
		}
		if match := enbPattern.FindStringSubmatch(line); len(match) > 1 {
			currentENB = match[1]
		}
		if imsiPattern.MatchString(line) {
			foundIMSI = true
		}
	}

	for id := range mmeSet {
		mmeIDs = append(mmeIDs, id)
	}
	for id := range enbSet {
		enbIDs = append(enbIDs, id)
	}
	return
}

// GTPv2Resolver resolves GTPv2 filters for an IMSI
type GTPv2Resolver struct {
	mu    sync.Mutex
	teids []string // Cached TEIDs for GTP-U
}

// NewGTPv2Resolver creates a new GTPv2 resolver
func NewGTPv2Resolver() *GTPv2Resolver {
	return &GTPv2Resolver{}
}

// ResolveFilter resolves GTPv2 display filter for an IMSI
func (r *GTPv2Resolver) ResolveFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Try direct IMSI field
	teids := r.extractTEIDs(ctx, pcapFile, imsi)

	// Cache for GTP-U (thread-safe)
	r.mu.Lock()
	r.teids = teids
	r.mu.Unlock()

	var parts []string

	// Add direct IMSI filter using e212.imsi (gtpv2.imsi is not a valid field)
	// Use combined filter to restrict to GTPv2 protocol
	parts = append(parts, fmt.Sprintf("(gtpv2 && e212.imsi == \"%s\")", imsi))

	// Add TEID filters
	for _, teid := range teids {
		parts = append(parts, fmt.Sprintf("gtpv2.teid == %s", teid))
	}

	return strings.Join(parts, " || "), nil
}

// ResolveGTPUFilter resolves GTP-U filter based on TEIDs from GTPv2
func (r *GTPv2Resolver) ResolveGTPUFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	// GTP-U runs in parallel with GTPv2, so we need to extract TEIDs independently
	// This ensures we don't depend on GTPv2 finishing first
	teids := r.extractTEIDs(ctx, pcapFile, imsi)

	if len(teids) == 0 {
		return "", nil
	}

	var parts []string
	for _, teid := range teids {
		parts = append(parts, fmt.Sprintf("gtp.teid == %s", teid))
	}

	return strings.Join(parts, " || "), nil
}

func (r *GTPv2Resolver) extractTEIDs(ctx context.Context, pcapFile, imsi string) []string {
	teidSet := make(map[string]bool)

	// Try to get TEIDs from GTPv2 messages with this IMSI
	result, err := tshark.TsharkVerbose(ctx, pcapFile, "gtpv2")
	if err != nil {
		return nil
	}

	teidPattern := regexp.MustCompile(`TEID[^:]*:\s*(0x[0-9a-fA-F]+|\d+)`)
	imsiPattern := regexp.MustCompile(`IMSI:\s*` + regexp.QuoteMeta(imsi))

	lines := strings.Split(result.Stdout, "\n")
	var foundIMSI bool
	var currentTEIDs []string

	for _, line := range lines {
		if strings.HasPrefix(line, "Frame ") {
			if foundIMSI {
				for _, teid := range currentTEIDs {
					teidSet[teid] = true
				}
			}
			foundIMSI = false
			currentTEIDs = nil
		}

		if match := teidPattern.FindStringSubmatch(line); len(match) > 1 {
			if match[1] != "0x00000000" && match[1] != "0" {
				currentTEIDs = append(currentTEIDs, match[1])
			}
		}
		if imsiPattern.MatchString(line) {
			foundIMSI = true
		}
	}

	var teids []string
	for teid := range teidSet {
		teids = append(teids, teid)
	}
	return teids
}

// getMSIN extracts MSIN from IMSI (last 9-10 digits after MCC+MNC)
func getMSIN(imsi string) string {
	if len(imsi) >= 15 {
		return imsi[5:] // MCC(3) + MNC(2) = 5, rest is MSIN
	} else if len(imsi) >= 14 {
		return imsi[5:]
	}
	return imsi
}

// UEIPResolver resolves IP layer filters for an IMSI by extracting UE IPv4 from NGAP/S1AP IE/NAS
// This is a "fake" protocol - when selected, it parses UE IPv4 and generates ip.addr filter
type UEIPResolver struct {
	ngapResolver *NGAPResolver
	s1apResolver *S1APResolver
}

// NewUEIPResolver creates a new UEIP resolver
func NewUEIPResolver(ngap *NGAPResolver, s1ap *S1APResolver) *UEIPResolver {
	return &UEIPResolver{
		ngapResolver: ngap,
		s1apResolver: s1ap,
	}
}

// ResolveFilter resolves IP layer display filter for an IMSI
// Extracts UE IPv4 from NGAP/S1AP IE (including nested NAS) and returns ip.addr filter
// This is optional and allowed to fail - returns empty string on failure
func (r *UEIPResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Step A: Get NGAP/S1AP filters to narrow down the scan scope
	var scanFilters []string

	// Try NGAP first (5G)
	ngapFilter, _ := r.ngapResolver.ResolveFilter(ctx, pcapFile, imsi)
	if ngapFilter != "" {
		scanFilters = append(scanFilters, "("+ngapFilter+")")
	}

	// Try S1AP (LTE)
	s1apFilter, _ := r.s1apResolver.ResolveFilter(ctx, pcapFile, imsi)
	if s1apFilter != "" {
		scanFilters = append(scanFilters, "("+s1apFilter+")")
	}

	// If no base filters found, we can't narrow down - try scanning all NGAP/S1AP
	var scanFilter string
	if len(scanFilters) > 0 {
		scanFilter = strings.Join(scanFilters, " || ")
	} else {
		// Fallback: scan all NGAP and S1AP messages for this IMSI
		scanFilter = fmt.Sprintf("(ngap && e212.imsi == \"%s\") || (s1ap && e212.imsi == \"%s\")", imsi, imsi)
	}

	// Step B: Scan the narrowed packets for UE IPv4
	result, err := tshark.TsharkVerbose(ctx, pcapFile, scanFilter)
	if err != nil {
		// Allow failure - return empty
		return "", nil
	}

	ueIPv4 := r.extractUEIPv4(result.Stdout)
	if ueIPv4 == "" {
		// No UE IP found - this is allowed
		return "", nil
	}

	// Step C: Generate IP layer filter
	return fmt.Sprintf("ip.addr == %s", ueIPv4), nil
}

// extractUEIPv4 extracts UE IPv4 address from tshark verbose output
// Looks for IPv4 in IE/NAS fields, avoiding external IP headers
func (r *UEIPResolver) extractUEIPv4(output string) string {
	// IPv4 pattern
	ipv4Pattern := regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

	// Keywords that indicate UE IP address in IE/NAS (case-insensitive matching via line content)
	// These are typically found in PDU Session / Bearer Context / NAS messages
	ueIPKeywords := []string{
		"PDU Address",
		"PDN Address",
		"IPv4 address",
		"End User Address",
		"UE IPv4",
		"Allocated IP",
		"IP Address:",
		"pDUSessionAggregateMaximumBitRate", // Context near IP allocation
		"pDUAddress",
		"PDU session",
		"transportLayerAddress", // May contain UE address in some contexts
	}

	// Keywords that indicate we should skip the line (external/network addresses)
	skipKeywords := []string{
		"Source Address:",
		"Destination Address:",
		"Source:",
		"Destination:",
		"src:",
		"dst:",
		"GTP",        // GTP header addresses are network addresses
		"SCTP",       // SCTP addresses
		"gNB-",       // gNB addresses
		"eNB-",       // eNB addresses
		"AMF",        // AMF addresses (unless it's AMF UE context)
		"MME",        // MME addresses
		"UPF",        // UPF addresses
		"SGW",        // SGW addresses
		"PGW",        // PGW addresses
		"N3 address", // N3 interface address (network side)
		"N9 address", // N9 interface address
	}

	// Collect candidate IPs with their context
	type ipCandidate struct {
		ip       string
		priority int // higher is better
	}
	var candidates []ipCandidate

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		lineLower := strings.ToLower(line)

		// Skip lines with network infrastructure keywords
		shouldSkip := false
		for _, skip := range skipKeywords {
			if strings.Contains(lineLower, strings.ToLower(skip)) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
			continue
		}

		// Check if line contains UE IP keywords
		hasUEKeyword := false
		for _, keyword := range ueIPKeywords {
			if strings.Contains(lineLower, strings.ToLower(keyword)) {
				hasUEKeyword = true
				break
			}
		}

		// Extract IPv4 from the line
		matches := ipv4Pattern.FindAllString(line, -1)
		for _, ip := range matches {
			if !isValidUEIPv4(ip) {
				continue
			}

			priority := 0
			if hasUEKeyword {
				priority += 10
			}
			// Prefer RFC1918 private addresses (typical for UE)
			if isPrivateIPv4(ip) {
				priority += 5
			}

			candidates = append(candidates, ipCandidate{ip: ip, priority: priority})
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	// Sort by priority (highest first) and return the best candidate
	bestIP := candidates[0]
	for _, c := range candidates[1:] {
		if c.priority > bestIP.priority {
			bestIP = c
		}
	}

	return bestIP.ip
}

// isValidUEIPv4 checks if an IPv4 string is valid and not a special address
func isValidUEIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	var octets [4]int
	for i, part := range parts {
		val := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			val = val*10 + int(c-'0')
		}
		if val > 255 {
			return false
		}
		octets[i] = val
	}

	// Skip special addresses
	// 0.0.0.0
	if octets[0] == 0 && octets[1] == 0 && octets[2] == 0 && octets[3] == 0 {
		return false
	}
	// 127.x.x.x (loopback)
	if octets[0] == 127 {
		return false
	}
	// 255.255.255.255 (broadcast)
	if octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255 {
		return false
	}
	// 224.0.0.0 - 239.255.255.255 (multicast)
	if octets[0] >= 224 && octets[0] <= 239 {
		return false
	}

	return true
}

// isPrivateIPv4 checks if an IPv4 is in RFC1918 private ranges
func isPrivateIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}

	var octets [4]int
	for i, part := range parts {
		val := 0
		for _, c := range part {
			val = val*10 + int(c-'0')
		}
		octets[i] = val
	}

	// 10.0.0.0/8
	if octets[0] == 10 {
		return true
	}
	// 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
	if octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if octets[0] == 192 && octets[1] == 168 {
		return true
	}
	// 100.64.0.0/10 (CGNAT, also commonly used for UE)
	if octets[0] == 100 && octets[1] >= 64 && octets[1] <= 127 {
		return true
	}

	return false
}

// teidToNgapBytes converts a TEID string (hex or decimal) to the xx:xx:xx:xx format
// used by ngap.gTP_TEID display filter. Returns empty string and false if conversion fails.
// Examples:
//   - "0x00000001" -> "00:00:00:01", true
//   - "1" -> "00:00:00:01", true
//   - "0x10000b4b" -> "10:00:0b:4b", true
func teidToNgapBytes(teid string) (string, bool) {
	var val uint64
	var err error

	teid = strings.TrimSpace(teid)
	if teid == "" {
		return "", false
	}

	if strings.HasPrefix(teid, "0x") || strings.HasPrefix(teid, "0X") {
		// Parse as hex
		val, err = strconv.ParseUint(teid[2:], 16, 32)
	} else {
		// Parse as decimal
		val, err = strconv.ParseUint(teid, 10, 32)
	}

	if err != nil {
		return "", false
	}

	// TEID is 32-bit (4 bytes)
	bytes := []byte{
		byte((val >> 24) & 0xFF),
		byte((val >> 16) & 0xFF),
		byte((val >> 8) & 0xFF),
		byte(val & 0xFF),
	}

	return fmt.Sprintf("%02x:%02x:%02x:%02x", bytes[0], bytes[1], bytes[2], bytes[3]), true
}

// SBIResolver resolves 5GC SBI filters for an IMSI.
//
// Note on tshark compatibility:
//   - In some environments/captures, tshark may not expose HTTP2 fields (or even label packets as HTTP2).
//     For example, packets might show as "HTTP/JSON" in _ws.col.Protocol, and http2.* fields may be absent.
//   - To stay robust, we correlate at the TCP level using tcp.stream, which is always available.
//     This still achieves the key goal: when the request contains imsi-<IMSI> but the response doesn't,
//     we include the response by including the whole tcp.stream (payload-bearing packets only).
type SBIResolver struct{}

func NewSBIResolver() *SBIResolver { return &SBIResolver{} }

func (r *SBIResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	imsiToken := "imsi-" + strings.TrimSpace(imsi)
	if imsiToken == "imsi-" {
		return "", nil
	}

	// Phase 1: find request frames containing imsi-<IMSI>.
	// Use frame contains so this works even if packets aren't dissected as HTTP2 by tshark.
	reqFilter := fmt.Sprintf(`frame contains "%s"`, imsiToken)

	// Phase 2: correlate to include responses on the same TCP stream.
	// We avoid depending on http2.streamid because it may not exist in some tshark builds.
	fieldsResult, err := tshark.TsharkFields(ctx, pcapFile, reqFilter, []string{"tcp.stream"})
	if err != nil {
		return "", err
	}
	if fieldsResult.ExitCode != 0 {
		// Best-effort: treat as no matches.
		return "", nil
	}
	if strings.TrimSpace(fieldsResult.Stdout) == "" {
		// No matched frames.
		return "", nil
	}

	// Collect unique tcp.stream ids.
	streams := make(map[string]struct{})
	lines := strings.Split(strings.TrimSpace(fieldsResult.Stdout), "\n")
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		// -T fields with a single -e outputs one field per line (no tabs).
		// But keep a small safety split in case separator changes.
		if idx := strings.Index(s, "\t"); idx >= 0 {
			s = strings.TrimSpace(s[:idx])
		}
		if s == "" {
			continue
		}
		streams[s] = struct{}{}
		if len(streams) >= 200 {
			break
		}
	}

	if len(streams) == 0 {
		return reqFilter, nil
	}

	// Build correlated filter.
	// Use tcp.len > 0 to avoid including pure ACK noise; still captures request/response payload packets.
	var parts []string
	parts = append(parts, "("+reqFilter+")")
	for s := range streams {
		parts = append(parts, fmt.Sprintf("(tcp.stream == %s && tcp.len > 0)", s))
	}
	return strings.Join(parts, " || "), nil
}
