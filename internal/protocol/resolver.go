package protocol

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"uepcap/internal/tshark"
)

// FilterResolver resolves display filters for IMSI + protocols
type FilterResolver struct {
	ngapResolver  *NGAPResolver
	pfcpResolver  *PFCPResolver
	s1apResolver  *S1APResolver
	gtpv2Resolver *GTPv2Resolver
}

// NewFilterResolver creates a new filter resolver
func NewFilterResolver() *FilterResolver {
	return &FilterResolver{
		ngapResolver:  NewNGAPResolver(),
		pfcpResolver:  NewPFCPResolver(),
		s1apResolver:  NewS1APResolver(),
		gtpv2Resolver: NewGTPv2Resolver(),
	}
}

// ResolveFilter resolves a combined display filter for an IMSI across multiple protocols
// Optimized: processes protocols in parallel for better performance
func (r *FilterResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string, protocols []string) (string, error) {
	type filterResult struct {
		proto  string
		filter string
		err    error
	}

	resultChan := make(chan filterResult, len(protocols))
	var wg sync.WaitGroup

	// Process protocols in parallel
	for _, proto := range protocols {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			var filter string
			var err error

			switch strings.ToLower(p) {
			case "ngap":
				filter, err = r.ngapResolver.ResolveFilter(ctx, pcapFile, imsi)
			case "pfcp":
				filter, err = r.pfcpResolver.ResolveFilter(ctx, pcapFile, imsi)
			case "s1ap":
				filter, err = r.s1apResolver.ResolveFilter(ctx, pcapFile, imsi)
			case "gtpv2":
				filter, err = r.gtpv2Resolver.ResolveFilter(ctx, pcapFile, imsi)
			case "gtpu":
				// GTP-U filter is derived from GTPv2 TEIDs
				filter, err = r.gtpv2Resolver.ResolveGTPUFilter(ctx, pcapFile, imsi)
			default:
				return
			}

			resultChan <- filterResult{proto: p, filter: filter, err: err}
		}(proto)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var filters []string
	for result := range resultChan {
		if result.err != nil {
			// Log but continue with other protocols
			continue
		}
		if result.filter != "" {
			filters = append(filters, "("+result.filter+")")
		}
	}

	if len(filters) == 0 {
		return "", nil
	}

	return strings.Join(filters, " || "), nil
}

// NGAPResolver resolves NGAP filters for an IMSI
type NGAPResolver struct{}

// NewNGAPResolver creates a new NGAP resolver
func NewNGAPResolver() *NGAPResolver {
	return &NGAPResolver{}
}

// ResolveFilter resolves NGAP display filter for an IMSI
func (r *NGAPResolver) ResolveFilter(ctx context.Context, pcapFile, imsi string) (string, error) {
	// Step 1: Find RAN-UE-NGAP-ID from InitialUEMessage containing MSIN
	msin := getMSIN(imsi)

	// Search InitialUEMessage for MSIN (multiple registrations = multiple RAN_UE_NGAP_IDs)
	result, err := tshark.TsharkVerbose(ctx, pcapFile, "ngap.procedureCode == 15")
	if err != nil {
		return "", err
	}

	ranIDs := r.extractRanIDsFromInitialUE(result.Stdout, msin)

	if len(ranIDs) == 0 {
		return "", nil
	}

	// Step 2: Find all AMF_UE_NGAP_IDs associated with these RAN_UE_NGAP_IDs
	amfIDs := r.findAMFIDsForRanIDs(ctx, pcapFile, ranIDs)

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

	return strings.Join(parts, " || "), nil
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
