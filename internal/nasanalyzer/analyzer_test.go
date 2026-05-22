package nasanalyzer

import "testing"

func TestParseFieldRowsCountsMMAndSMLayers(t *testing.T) {
	messages := parseFieldRows("100\t1.5\t10.0.0.1\t10.0.0.2\t\t\t46\t0\t0x67\t0xc1\t2\t9\t")
	if len(messages) != 2 {
		t.Fatalf("message count = %d, want 2", len(messages))
	}
	if messages[0].Category != CategoryMM || messages[0].MessageTypeCode != "0x67" {
		t.Fatalf("first message = %s/%s, want 5gmm/0x67", messages[0].Category, messages[0].MessageTypeCode)
	}
	if messages[1].Category != CategorySM || messages[1].MessageTypeCode != "0xc1" {
		t.Fatalf("second message = %s/%s, want 5gsm/0xc1", messages[1].Category, messages[1].MessageTypeCode)
	}
}

func TestFilterMMAndSMResultsSeparateCategories(t *testing.T) {
	result := analyze("sample.pcap", []*Message{
		{FrameNumber: 1, Category: CategoryMM, MessageTypeCode: "0x41", MessageType: MMMessageTypeName("0x41")},
		{FrameNumber: 2, Category: CategoryMM, MessageTypeCode: "0x43", MessageType: MMMessageTypeName("0x43")},
		{FrameNumber: 3, Category: CategorySM, MessageTypeCode: "0xc1", MessageType: SMMessageTypeName("0xc1")},
		{FrameNumber: 4, Category: CategorySM, MessageTypeCode: "0xc2", MessageType: SMMessageTypeName("0xc2")},
	})

	mm := FilterMMResult(result)
	if mm.Statistics.TotalMessages != 2 || mm.Statistics.MMMessages != 2 || mm.Statistics.SMMessages != 0 {
		t.Fatalf("mm stats = total %d mm %d sm %d, want 2/2/0", mm.Statistics.TotalMessages, mm.Statistics.MMMessages, mm.Statistics.SMMessages)
	}
	if mm.Statistics.PDUSession != 0 {
		t.Fatalf("mm pdu session flows = %d, want 0", mm.Statistics.PDUSession)
	}
	for _, msg := range mm.Messages {
		if msg.Category != CategoryMM {
			t.Fatalf("mm result contains category %s", msg.Category)
		}
	}

	sm := FilterSMResult(result)
	if sm.Statistics.TotalMessages != 2 || sm.Statistics.MMMessages != 0 || sm.Statistics.SMMessages != 2 {
		t.Fatalf("sm stats = total %d mm %d sm %d, want 2/0/2", sm.Statistics.TotalMessages, sm.Statistics.MMMessages, sm.Statistics.SMMessages)
	}
	if sm.Statistics.PDUSession != 1 {
		t.Fatalf("sm pdu session flows = %d, want 1", sm.Statistics.PDUSession)
	}
	for _, msg := range sm.Messages {
		if msg.Category != CategorySM {
			t.Fatalf("sm result contains category %s", msg.Category)
		}
	}
}

func TestMMMessageTypeNameIncludesServiceReject(t *testing.T) {
	if got := MMMessageTypeName("0x4d"); got != "Service Reject" {
		t.Fatalf("MMMessageTypeName(0x4d) = %q, want Service Reject", got)
	}
}
