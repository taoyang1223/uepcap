package api

import (
	"testing"

	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

func TestInferIPMappings_NGAP_BothSides38412_UsesMessageDirection(t *testing.T) {
	// Some environments may use SCTP port 38412 on both endpoints.
	// In that case, port-based inference is ambiguous; we should fall back to NGAP procedure direction.
	compactJSON := `[
  {
    "layers": {
      "src_ip": "172.18.200.21",
      "dst_ip": "172.18.200.62",
      "src_port": "38412",
      "dst_port": "38412",
      "proto": "sctp"
    },
    "application": {
      "ngap": {
        "procedureCode": "15",
        "procedure": "InitialUEMessage"
      }
    }
  }
]`

	mappings := InferIPMappings(compactJSON)
	got := map[string]string{}
	for _, m := range mappings {
		got[m.IP] = m.NE
	}

	if got["172.18.200.21"] != "gNB" {
		t.Fatalf("expected src IP to be gNB, got %q (all=%v)", got["172.18.200.21"], got)
	}
	if got["172.18.200.62"] != "AMF" {
		t.Fatalf("expected dst IP to be AMF, got %q (all=%v)", got["172.18.200.62"], got)
	}
}

func TestInferIPMappingsWithPacketColumns_NGAP_BothSides38412_UsesInfo(t *testing.T) {
	compactJSON := `[
  {
    "frame": { "number": "134" },
    "layers": {
      "src_ip": "172.18.200.21",
      "dst_ip": "172.18.200.62",
      "src_port": "38412",
      "dst_port": "38412",
      "proto": "sctp"
    },
    "application": {}
  }
]`

	cols := map[string]*tshark.PacketColumns{
		"134": {
			FrameNumber: "134",
			Protocol:    "NGAP/NAS-5GS",
			InfoClean:   "InitialUEMessage, Registration request",
		},
	}

	mappings := InferIPMappingsWithPacketColumns(compactJSON, cols)
	got := map[string]string{}
	for _, m := range mappings {
		got[m.IP] = m.NE
	}

	if got["172.18.200.21"] != "gNB" {
		t.Fatalf("expected src IP to be gNB, got %q (all=%v)", got["172.18.200.21"], got)
	}
	if got["172.18.200.62"] != "AMF" {
		t.Fatalf("expected dst IP to be AMF, got %q (all=%v)", got["172.18.200.62"], got)
	}
}
