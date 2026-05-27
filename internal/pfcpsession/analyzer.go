package pfcpsession

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/analysislimit"
	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

const (
	DefaultTimeout      = 3 * time.Second
	DefaultMessageLimit = analysislimit.DefaultMaxRows

	pfcpTransactionDisplayFilter = "(pfcp.msg_type == 1 || pfcp.msg_type == 2 || pfcp.msg_type == 5 || pfcp.msg_type == 6 || pfcp.msg_type == 7 || pfcp.msg_type == 8 || pfcp.msg_type == 9 || pfcp.msg_type == 10 || pfcp.msg_type == 12 || pfcp.msg_type == 13 || (pfcp.msg_type >= 50 && pfcp.msg_type <= 57))"
)

var tsharkSessionFields = []string{
	"frame.number",
	"frame.time_epoch",
	"ip.src",
	"ip.dst",
	"ipv6.src",
	"ipv6.dst",
	"udp.srcport",
	"udp.dstport",
	"pfcp.msg_type",
	"pfcp.seid",
	"pfcp.seqno",
	"pfcp.cause",
	"pfcp.f_seid.ipv4",
	"pfcp.f_seid.ipv6",
}

type Analyzer struct {
	timeout      time.Duration
	messageLimit int
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{timeout: DefaultTimeout, messageLimit: defaultMessageLimit()}
}

func (a *Analyzer) SetTimeout(timeout time.Duration) {
	if timeout > 0 {
		a.timeout = timeout
	}
}

func (a *Analyzer) SetMessageLimit(limit int) {
	if limit > 0 {
		a.messageLimit = limit
	}
}

func (a *Analyzer) AnalyzeFile(ctx context.Context, pcapFile string) (*AnalysisResult, error) {
	messages, truncated, err := a.readMessages(ctx, pcapFile)
	if err != nil {
		return nil, err
	}

	result := a.analyze(pcapFile, messages)
	result.Truncated = truncated
	if truncated {
		result.MessageLimit = a.messageLimit
	}
	return result, nil
}

type StreamProgress struct {
	ProcessedMessages int  `json:"processed_messages"`
	ChunkIndex        int  `json:"chunk_index"`
	ChunkMessages     int  `json:"chunk_messages"`
	ChunkTarget       int  `json:"chunk_target"`
	Done              bool `json:"done,omitempty"`
}

func (a *Analyzer) AnalyzeFileStream(ctx context.Context, pcapFile string, batchMessages int, onUpdate func(StreamProgress, *AnalysisResult) error) (*AnalysisResult, error) {
	if batchMessages <= 0 {
		batchMessages = 5000
	}
	state := newStreamState(pcapFile, a.timeout)
	chunkMessages := 0
	chunkIndex := 1
	emit := func(done bool) error {
		return onUpdate(StreamProgress{
			ProcessedMessages: state.totalPackets,
			ChunkIndex:        chunkIndex,
			ChunkMessages:     chunkMessages,
			ChunkTarget:       batchMessages,
			Done:              done,
		}, state.result(done))
	}

	result, err := tshark.TsharkFieldsStream(ctx, pcapFile, pfcpTransactionDisplayFilter, tsharkSessionFields, func(line string) error {
		msg := parseFieldRow(line)
		if msg == nil {
			return nil
		}
		state.add(msg)
		chunkMessages++
		if chunkMessages >= batchMessages {
			if err := emit(false); err != nil {
				return err
			}
			chunkIndex++
			chunkMessages = 0
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if result.ExitCode != 0 {
		return nil, fmt.Errorf("tshark PFCP transaction analysis failed: %s", strings.TrimSpace(result.Stderr))
	}
	final := state.result(true)
	if err := emit(true); err != nil {
		return nil, err
	}
	return final, nil
}

var errPFCPMessageLimitReached = errors.New("PFCP message limit reached")

func (a *Analyzer) readMessages(ctx context.Context, pcapFile string) ([]*Message, bool, error) {
	messages := make([]*Message, 0, 4096)
	truncated := false
	result, err := tshark.TsharkFieldsStream(ctx, pcapFile, pfcpTransactionDisplayFilter, tsharkSessionFields, func(line string) error {
		msg := parseFieldRow(line)
		if msg == nil {
			return nil
		}
		if a.messageLimit > 0 && len(messages) >= a.messageLimit {
			truncated = true
			return errPFCPMessageLimitReached
		}
		messages = append(messages, msg)
		return nil
	})
	if errors.Is(err, errPFCPMessageLimitReached) {
		return messages, truncated, nil
	}
	if err != nil {
		return nil, false, err
	}
	if result.ExitCode != 0 {
		return nil, false, fmt.Errorf("tshark PFCP transaction analysis failed: %s", strings.TrimSpace(result.Stderr))
	}
	return messages, truncated, nil
}

func (a *Analyzer) analyze(filename string, messages []*Message) *AnalysisResult {
	result := &AnalysisResult{
		Filename:     filename,
		AnalyzedAt:   time.Now(),
		TotalPackets: len(messages),
	}
	sessionEstablishmentResponseSEIDs := collectSessionEstablishmentResponseSEIDsByHeader(messages)
	sessionPeerSEIDs := collectSessionPeerSEIDs(messages)

	requests := make(map[string][]*Message)
	responses := make(map[string][]*Message)
	requestCounts := make(map[string][]int)

	for _, msg := range messages {
		if !isSessionMessage(msg.MessageTypeCode) {
			continue
		}

		key := makeKey(msg)
		if isRequest(msg.MessageTypeCode) {
			retransmitKey := makeRetransmitKey(msg)
			requestCounts[retransmitKey] = append(requestCounts[retransmitKey], msg.FrameNumber)
			requests[key] = append(requests[key], msg)
			continue
		}
		if isResponse(msg.MessageTypeCode) {
			reverseKey := makeReverseKey(msg)
			responses[reverseKey] = append(responses[reverseKey], msg)
		}
	}

	transactions := make([]*Transaction, 0, len(requests))
	txID := 0
	for key, reqs := range requests {
		if len(reqs) == 0 {
			continue
		}
		resps := responses[key]
		usedResponses := make([]bool, len(resps))
		seenRetries := make(map[string]int)
		for _, req := range reqs {
			txID++
			if respIndex := findMatchingResponse(req, resps, usedResponses, sessionPeerSEIDs); respIndex >= 0 {
				usedResponses[respIndex] = true
				transactions = append(transactions, newCompletedTransaction(txID, req, resps[respIndex], sessionEstablishmentResponseSEIDs, requestCounts, a.timeout))
				continue
			}
			tx := newTransaction(txID, req, sessionEstablishmentResponseSEIDs)
			tx.Status = StatusNoResponse
			retransmitKey := makeRetransmitKey(req)
			if seenRetries[retransmitKey] > 0 {
				tx.RetransmitCount = 1
			}
			seenRetries[retransmitKey]++
			transactions = append(transactions, tx)
		}
	}

	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].RequestTime.Before(transactions[j].RequestTime)
	})
	for i, tx := range transactions {
		tx.ID = fmt.Sprintf("tx-%d", i+1)
	}

	result.Transactions = transactions
	result.Statistics = calculateStatistics(transactions)
	return result
}

type streamState struct {
	filename                          string
	timeout                           time.Duration
	totalPackets                      int
	sessionEstablishmentResponseSEIDs map[uint64][]uint64
	sessionEstablishmentSeen          map[uint64]map[uint64]bool
	sessionPeerSEIDs                  map[uint64]map[uint64]bool
	pendingRequests                   map[string][]*Message
	orphanResponses                   map[string][]*Message
	requestCounts                     map[string][]int
	completed                         []*Transaction
}

func newStreamState(filename string, timeout time.Duration) *streamState {
	return &streamState{
		filename:                          filename,
		timeout:                           timeout,
		sessionEstablishmentResponseSEIDs: make(map[uint64][]uint64),
		sessionEstablishmentSeen:          make(map[uint64]map[uint64]bool),
		sessionPeerSEIDs:                  make(map[uint64]map[uint64]bool),
		pendingRequests:                   make(map[string][]*Message),
		orphanResponses:                   make(map[string][]*Message),
		requestCounts:                     make(map[string][]int),
	}
}

func (s *streamState) add(msg *Message) {
	s.totalPackets++
	s.collectSessionEstablishmentResponseSEIDs(msg)
	if !isSessionMessage(msg.MessageTypeCode) {
		return
	}
	if isRequest(msg.MessageTypeCode) {
		retransmitKey := makeRetransmitKey(msg)
		s.requestCounts[retransmitKey] = append(s.requestCounts[retransmitKey], msg.FrameNumber)
		key := makeKey(msg)
		s.pendingRequests[key] = append(s.pendingRequests[key], msg)
		reqIndex := len(s.pendingRequests[key]) - 1
		if respIndex := s.findOrphanResponseIndex(key, msg); respIndex >= 0 {
			resp := s.orphanResponses[key][respIndex]
			s.orphanResponses[key] = removeMessageAt(s.orphanResponses[key], respIndex)
			if len(s.orphanResponses[key]) == 0 {
				delete(s.orphanResponses, key)
			}
			s.completeAt(key, reqIndex, resp)
		}
		return
	}
	if isResponse(msg.MessageTypeCode) {
		key := makeReverseKey(msg)
		if reqIndex := s.findPendingRequestIndex(key, msg); reqIndex >= 0 {
			s.completeAt(key, reqIndex, msg)
			return
		}
		s.orphanResponses[key] = append(s.orphanResponses[key], msg)
	}
}

func (s *streamState) collectSessionEstablishmentResponseSEIDs(msg *Message) {
	if msg == nil || msg.MessageTypeCode != 51 || msg.HeaderSEID == 0 {
		return
	}
	seen := s.sessionEstablishmentSeen[msg.HeaderSEID]
	if seen == nil {
		seen = make(map[uint64]bool)
		s.sessionEstablishmentSeen[msg.HeaderSEID] = seen
	}
	seids := s.sessionEstablishmentResponseSEIDs[msg.HeaderSEID]
	addUniqueSEIDs(&seids, seen, msg.HeaderSEID, msg.FSEID)
	s.sessionEstablishmentResponseSEIDs[msg.HeaderSEID] = seids
	addSEIDPeer(s.sessionPeerSEIDs, msg.HeaderSEID, msg.FSEID)
}

func (s *streamState) findPendingRequestIndex(key string, resp *Message) int {
	reqs := s.pendingRequests[key]
	used := make([]bool, 0)
	return findMatchingResponseRequest(resp, reqs, used, s.sessionPeerSEIDs)
}

func (s *streamState) findOrphanResponseIndex(key string, req *Message) int {
	resps := s.orphanResponses[key]
	used := make([]bool, len(resps))
	return findMatchingResponse(req, resps, used, s.sessionPeerSEIDs)
}

func (s *streamState) completeAt(key string, reqIndex int, resp *Message) {
	reqs := s.pendingRequests[key]
	if reqIndex < 0 || reqIndex >= len(reqs) {
		return
	}
	req := reqs[reqIndex]
	s.completed = append(s.completed, newCompletedTransaction(0, req, resp, s.sessionEstablishmentResponseSEIDs, s.requestCounts, s.timeout))
	s.pendingRequests[key] = removeMessageAt(reqs, reqIndex)
	if len(s.pendingRequests[key]) == 0 {
		delete(s.pendingRequests, key)
	}
}

func (s *streamState) result(final bool) *AnalysisResult {
	transactions := make([]*Transaction, 0, len(s.completed)+len(s.pendingRequests))
	transactions = append(transactions, s.completed...)
	for _, reqs := range s.pendingRequests {
		seenRetries := make(map[string]int)
		for _, req := range reqs {
			tx := newTransaction(0, req, s.sessionEstablishmentResponseSEIDs)
			tx.Status = StatusNoResponse
			retransmitKey := makeRetransmitKey(req)
			if final {
				if frames := s.requestCounts[retransmitKey]; len(frames) > 1 {
					tx.RetransmitCount = len(frames) - 1
					tx.RetransmitFrames = append([]int(nil), frames[1:]...)
				}
			} else if seenRetries[retransmitKey] > 0 {
				tx.RetransmitCount = 1
			}
			seenRetries[retransmitKey]++
			transactions = append(transactions, tx)
		}
	}
	sort.Slice(transactions, func(i, j int) bool {
		return transactions[i].RequestTime.Before(transactions[j].RequestTime)
	})
	for i, tx := range transactions {
		tx.ID = fmt.Sprintf("tx-%d", i+1)
	}
	return &AnalysisResult{
		Filename:     s.filename,
		AnalyzedAt:   time.Now(),
		TotalPackets: s.totalPackets,
		Statistics:   calculateStatistics(transactions),
		Transactions: transactions,
	}
}

func newCompletedTransaction(id int, req, resp *Message, establishmentResponseSEIDs map[uint64][]uint64, requestCounts map[string][]int, timeout time.Duration) *Transaction {
	tx := newTransaction(id, req, establishmentResponseSEIDs)
	if frames := requestCounts[makeRetransmitKey(req)]; len(frames) > 1 {
		tx.RetransmitCount = len(frames) - 1
		tx.RetransmitFrames = append([]int(nil), frames[1:]...)
	}
	tx.ResponseSEID = resp.HeaderSEID
	tx.ResponseFSEID = resp.FSEID
	tx.ResponseTime = &resp.Timestamp
	tx.ResponseFrame = &resp.FrameNumber
	tx.SEIDFilter = transactionSEIDFilter(establishmentResponseSEIDs, req, resp)

	responseTimeMs := resp.Timestamp.Sub(req.Timestamp).Seconds() * 1000
	tx.ResponseTimeMs = &responseTimeMs

	if resp.Cause != nil {
		tx.Cause = resp.Cause
		tx.CauseName = CauseName(*resp.Cause)
		if *resp.Cause == CauseRequestAccepted {
			if resp.Timestamp.Sub(req.Timestamp) > timeout {
				tx.Status = StatusTimeout
			} else {
				tx.Status = StatusSuccess
			}
		} else {
			tx.Status = StatusFailed
		}
	} else {
		tx.Status = StatusSuccess
	}
	return tx
}

func findMatchingResponse(req *Message, responses []*Message, used []bool, peers map[uint64]map[uint64]bool) int {
	for i, resp := range responses {
		if i < len(used) && used[i] {
			continue
		}
		if messagesCanMatch(req, resp, peers) {
			return i
		}
	}
	return -1
}

func findMatchingResponseRequest(resp *Message, requests []*Message, used []bool, peers map[uint64]map[uint64]bool) int {
	for i, req := range requests {
		if i < len(used) && used[i] {
			continue
		}
		if messagesCanMatch(req, resp, peers) {
			return i
		}
	}
	return -1
}

func messagesCanMatch(req, resp *Message, peers map[uint64]map[uint64]bool) bool {
	if req == nil || resp == nil {
		return false
	}
	if !isRequest(req.MessageTypeCode) || !isResponse(resp.MessageTypeCode) {
		return false
	}
	if messageTypeCategory(req.MessageTypeCode) != messageTypeCategory(resp.MessageTypeCode) {
		return false
	}
	if req.SequenceNumber != resp.SequenceNumber {
		return false
	}
	if req.SourceIP != resp.DestinationIP || req.DestinationIP != resp.SourceIP {
		return false
	}
	if !resp.Timestamp.IsZero() && !req.Timestamp.IsZero() && resp.Timestamp.Before(req.Timestamp) {
		return false
	}
	if !requiresSessionSEIDMatch(req.MessageTypeCode) {
		return true
	}

	reqSEIDs := transactionMatchSEIDs(req)
	respSEIDs := transactionMatchSEIDs(resp)
	if len(reqSEIDs) == 0 || len(respSEIDs) == 0 {
		return true
	}
	for _, reqSEID := range reqSEIDs {
		for _, respSEID := range respSEIDs {
			if seidsCompatible(reqSEID, respSEID, peers) {
				return true
			}
		}
	}
	if hasAnySEIDPeer(reqSEIDs, peers) || hasAnySEIDPeer(respSEIDs, peers) {
		return false
	}
	return true
}

func requiresSessionSEIDMatch(msgType uint8) bool {
	switch msgType {
	case 50, 51, 52, 53, 54, 55, 56, 57:
		return true
	default:
		return false
	}
}

func transactionMatchSEIDs(msg *Message) []uint64 {
	if msg == nil {
		return nil
	}
	values := make([]uint64, 0, 2)
	seen := make(map[uint64]bool, 2)
	if msg.MessageTypeCode == 50 && msg.FSEID != 0 {
		addUniqueSEIDs(&values, seen, msg.FSEID)
		return values
	}
	addUniqueSEIDs(&values, seen, msg.HeaderSEID, msg.FSEID)
	return values
}

func seidsCompatible(left, right uint64, peers map[uint64]map[uint64]bool) bool {
	if left == 0 || right == 0 {
		return false
	}
	if left == right {
		return true
	}
	return peers[left][right] || peers[right][left]
}

func hasAnySEIDPeer(values []uint64, peers map[uint64]map[uint64]bool) bool {
	for _, value := range values {
		if len(peers[value]) > 0 {
			return true
		}
	}
	return false
}

func removeMessageAt(messages []*Message, index int) []*Message {
	if index < 0 || index >= len(messages) {
		return messages
	}
	copy(messages[index:], messages[index+1:])
	return messages[:len(messages)-1]
}

func newTransaction(id int, req *Message, establishmentResponseSEIDs map[uint64][]uint64) *Transaction {
	return &Transaction{
		ID:              fmt.Sprintf("tx-%d", id),
		RequestSEID:     req.HeaderSEID,
		RequestFSEID:    req.FSEID,
		SequenceNumber:  req.SequenceNumber,
		MessageType:     messageTypeCategory(req.MessageTypeCode),
		MessageTypeCode: req.MessageTypeCode,
		SourceIP:        req.SourceIP,
		DestinationIP:   req.DestinationIP,
		RequestTime:     req.Timestamp,
		RequestFrame:    req.FrameNumber,
		WiresharkFilter: transactionFilter(req),
		SEIDFilter:      transactionSEIDFilter(establishmentResponseSEIDs, req),
	}
}

func parseFieldRows(output string) []*Message {
	lines := strings.Split(strings.TrimRight(output, "\r\n"), "\n")
	messages := make([]*Message, 0, len(lines))

	for _, line := range lines {
		if msg := parseFieldRow(line); msg != nil {
			messages = append(messages, msg)
		}
	}

	return messages
}

func parseFieldRow(line string) *Message {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	cols := strings.Split(line, "\t")
	for len(cols) < len(tsharkSessionFields) {
		cols = append(cols, "")
	}

	msg := &Message{
		FrameNumber:     parseInt(cols[0]),
		Timestamp:       parseEpoch(cols[1]),
		SourceIP:        firstNonEmpty(cols[2], cols[4]),
		DestinationIP:   firstNonEmpty(cols[3], cols[5]),
		SourcePort:      uint16(parseInt(cols[6])),
		DestinationPort: uint16(parseInt(cols[7])),
		MessageTypeCode: uint8(parseInt(firstValue(cols[8]))),
		SequenceNumber:  uint32(parseInt(firstValue(cols[10]))),
		FSEIDIPv4:       firstValue(cols[12]),
		FSEIDIPv6:       firstValue(cols[13]),
	}

	seids := parseUintValues(cols[9])
	if len(seids) > 0 {
		msg.HeaderSEID = seids[0]
		msg.FSEID = seids[len(seids)-1]
	}
	if cause := firstValue(cols[11]); cause != "" {
		causeVal := uint8(parseInt(cause))
		msg.Cause = &causeVal
	}

	if msg.MessageTypeCode == 0 || net.ParseIP(msg.SourceIP) == nil || net.ParseIP(msg.DestinationIP) == nil {
		return nil
	}
	return msg
}

func defaultMessageLimit() int {
	return analysislimit.MaxRows("UEPCAP_PFCP_ANALYSIS_MAX_MESSAGES")
}

func makeKey(msg *Message) string {
	return fmt.Sprintf("%s:%s:%d:%s", msg.SourceIP, msg.DestinationIP, msg.SequenceNumber, messageTypeCategory(msg.MessageTypeCode))
}

func makeReverseKey(msg *Message) string {
	return fmt.Sprintf("%s:%s:%d:%s", msg.DestinationIP, msg.SourceIP, msg.SequenceNumber, messageTypeCategory(msg.MessageTypeCode))
}

func makeRetransmitKey(msg *Message) string {
	return fmt.Sprintf(
		"%s:%s:%d:%d:%d:%d:%s:%s",
		msg.SourceIP,
		msg.DestinationIP,
		msg.MessageTypeCode,
		msg.SequenceNumber,
		msg.HeaderSEID,
		msg.FSEID,
		msg.FSEIDIPv4,
		msg.FSEIDIPv6,
	)
}

func collectSessionEstablishmentResponseSEIDsByHeader(messages []*Message) map[uint64][]uint64 {
	seidsByHeader := make(map[uint64][]uint64)
	seenByHeader := make(map[uint64]map[uint64]bool)
	for _, msg := range messages {
		if msg == nil || msg.MessageTypeCode != 51 || msg.HeaderSEID == 0 {
			continue
		}
		seen := seenByHeader[msg.HeaderSEID]
		if seen == nil {
			seen = make(map[uint64]bool)
			seenByHeader[msg.HeaderSEID] = seen
		}
		seids := seidsByHeader[msg.HeaderSEID]
		addUniqueSEIDs(&seids, seen, msg.HeaderSEID, msg.FSEID)
		seidsByHeader[msg.HeaderSEID] = seids
	}
	return seidsByHeader
}

func collectSessionPeerSEIDs(messages []*Message) map[uint64]map[uint64]bool {
	peers := make(map[uint64]map[uint64]bool)
	for _, msg := range messages {
		if msg == nil || msg.MessageTypeCode != 51 {
			continue
		}
		addSEIDPeer(peers, msg.HeaderSEID, msg.FSEID)
	}
	return peers
}

func addSEIDPeer(peers map[uint64]map[uint64]bool, left, right uint64) {
	if left == 0 || right == 0 || left == right {
		return
	}
	if peers[left] == nil {
		peers[left] = make(map[uint64]bool)
	}
	if peers[right] == nil {
		peers[right] = make(map[uint64]bool)
	}
	peers[left][right] = true
	peers[right][left] = true
}

func transactionSEIDFilter(establishmentResponseSEIDs map[uint64][]uint64, messages ...*Message) string {
	var seids []uint64
	seen := make(map[uint64]bool)
	addAssociatedEstablishmentResponseSEIDs(&seids, seen, establishmentResponseSEIDs, messages...)
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		addUniqueSEIDs(&seids, seen, msg.HeaderSEID, msg.FSEID)
	}
	return formatSEIDFilter(seids)
}

func addAssociatedEstablishmentResponseSEIDs(out *[]uint64, seen map[uint64]bool, seidsByHeader map[uint64][]uint64, messages ...*Message) {
	headerSeen := make(map[uint64]bool)
	for _, msg := range messages {
		if msg == nil {
			continue
		}
		for _, candidate := range []uint64{msg.HeaderSEID, msg.FSEID} {
			if candidate == 0 || headerSeen[candidate] {
				continue
			}
			headerSeen[candidate] = true
			addUniqueSEIDs(out, seen, seidsByHeader[candidate]...)
		}
	}
}

func addUniqueSEIDs(out *[]uint64, seen map[uint64]bool, values ...uint64) {
	for _, seid := range values {
		if seid == 0 || seen[seid] {
			continue
		}
		seen[seid] = true
		*out = append(*out, seid)
	}
}

func formatSEIDFilter(seids []uint64) string {
	parts := make([]string, 0, len(seids))
	for _, seid := range seids {
		parts = append(parts, fmt.Sprintf("(pfcp.seid == 0x%016X)", seid))
	}
	return strings.Join(parts, " || ")
}

func transactionFilter(msg *Message) string {
	parts := []string{
		transactionMessageTypeFilter(msg.MessageTypeCode),
		fmt.Sprintf("pfcp.seqno == %d", msg.SequenceNumber),
		addressFilter(msg.SourceIP),
		addressFilter(msg.DestinationIP),
	}
	if msg.HeaderSEID != 0 {
		parts = append(parts, fmt.Sprintf("pfcp.seid == %d", msg.HeaderSEID))
	}
	return strings.Join(parts, " && ")
}

func transactionMessageTypeFilter(msgType uint8) string {
	switch msgType {
	case 1, 2:
		return "(pfcp.msg_type == 1 || pfcp.msg_type == 2)"
	case 5, 6:
		return "(pfcp.msg_type == 5 || pfcp.msg_type == 6)"
	case 7, 8:
		return "(pfcp.msg_type == 7 || pfcp.msg_type == 8)"
	case 9, 10:
		return "(pfcp.msg_type == 9 || pfcp.msg_type == 10)"
	case 12, 13:
		return "(pfcp.msg_type == 12 || pfcp.msg_type == 13)"
	case 50, 51:
		return "(pfcp.msg_type == 50 || pfcp.msg_type == 51)"
	case 52, 53:
		return "(pfcp.msg_type == 52 || pfcp.msg_type == 53)"
	case 54, 55:
		return "(pfcp.msg_type == 54 || pfcp.msg_type == 55)"
	case 56, 57:
		return "(pfcp.msg_type == 56 || pfcp.msg_type == 57)"
	default:
		return fmt.Sprintf("pfcp.msg_type == %d", msgType)
	}
}

func addressFilter(ip string) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("ipv6.addr == %s", ip)
	}
	return fmt.Sprintf("ip.addr == %s", ip)
}

func calculateStatistics(transactions []*Transaction) Statistics {
	stats := Statistics{TotalTransactions: len(transactions), MinResponseTimeMs: -1}
	var responseTotal float64
	var responseCount int

	for _, tx := range transactions {
		switch tx.Status {
		case StatusSuccess:
			stats.Success++
		case StatusFailed:
			stats.Failed++
		case StatusNoResponse:
			stats.NoResponse++
		case StatusTimeout:
			stats.Timeout++
		}

		if tx.RetransmitCount > 0 {
			stats.Retransmit++
		}

		switch tx.MessageType {
		case "Heartbeat":
			stats.Heartbeat++
		case "Association Setup":
			stats.AssociationSetup++
		case "Association Update":
			stats.AssociationUpdate++
		case "Association Release":
			stats.AssociationRelease++
		case "Node Report":
			stats.NodeReport++
		case "Session Establishment":
			stats.SessionEstablishment++
		case "Session Modification":
			stats.SessionModification++
		case "Session Deletion":
			stats.SessionDeletion++
		case "Session Report":
			stats.SessionReport++
		}

		if tx.ResponseTimeMs != nil {
			responseTotal += *tx.ResponseTimeMs
			responseCount++
			if stats.MinResponseTimeMs < 0 || *tx.ResponseTimeMs < stats.MinResponseTimeMs {
				stats.MinResponseTimeMs = *tx.ResponseTimeMs
			}
			if *tx.ResponseTimeMs > stats.MaxResponseTimeMs {
				stats.MaxResponseTimeMs = *tx.ResponseTimeMs
			}
		}
	}

	if responseCount > 0 {
		stats.AvgResponseTimeMs = responseTotal / float64(responseCount)
	}
	if stats.MinResponseTimeMs < 0 {
		stats.MinResponseTimeMs = 0
	}

	return stats
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = firstValue(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func firstValue(field string) string {
	values := splitValues(field)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func splitValues(field string) []string {
	field = strings.TrimSpace(field)
	if field == "" {
		return nil
	}
	raw := strings.FieldsFunc(field, func(r rune) bool {
		return r == ',' || r == ';'
	})
	values := make([]string, 0, len(raw))
	for _, value := range raw {
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

func parseUintValues(field string) []uint64 {
	raw := splitValues(field)
	values := make([]uint64, 0, len(raw))
	for _, value := range raw {
		parsed, ok := parseUint(value)
		if ok {
			values = append(values, parsed)
		}
	}
	return values
}

func parseUint(value string) (uint64, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if idx := strings.IndexAny(value, " \t("); idx >= 0 {
		value = value[:idx]
	}
	var (
		parsed uint64
		err    error
	)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		parsed, err = strconv.ParseUint(value[2:], 16, 64)
	} else {
		parsed, err = strconv.ParseUint(value, 10, 64)
	}
	return parsed, err == nil
}

func parseInt(value string) int {
	parsed, ok := parseUint(value)
	if !ok {
		return 0
	}
	return int(parsed)
}

func parseEpoch(value string) time.Time {
	value = firstValue(value)
	if value == "" {
		return time.Time{}
	}
	epoch, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return time.Time{}
	}
	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * 1e9)
	return time.Unix(sec, nsec)
}
