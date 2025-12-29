// Package httpapi provides an embeddable HTTP API for uepcap PCAP analysis.
//
// This package enables Go projects to integrate uepcap's signaling analysis
// capabilities directly into their HTTP servers. It supports:
//
//   - PCAP file upload and merging
//   - IMSI scanning from signaling protocols (NGAP, PFCP, S1AP, GTPv2)
//   - Protocol filter resolution for packet export
//   - Signaling flow diagram generation with protocol-based IP→NE mapping
//
// # Quick Start
//
// Add uepcap to your project:
//
//	go get gitee.com/yangdadayyds/uepcap
//
// Embed the HTTP API in your server:
//
//	package main
//
//	import (
//	    "context"
//	    "net/http"
//	    "time"
//
//	    uepcap "gitee.com/yangdadayyds/uepcap"
//	    "gitee.com/yangdadayyds/uepcap/httpapi"
//	)
//
//	func main() {
//	    handler, _ := httpapi.New(uepcap.Config{
//	        DataDir: "./data",
//	        JobTTL:  time.Hour,
//	        MaxJobs: 3,
//	    })
//
//	    ctx := context.Background()
//	    handler.Start(ctx)
//
//	    mux := http.NewServeMux()
//	    handler.RegisterRoutes(mux)
//
//	    http.ListenAndServe(":8080", mux)
//	}
//
// # API Routes
//
// The following routes are registered by [Handler.RegisterRoutes]:
//
// Job Management:
//
//	POST   /api/jobs                          Upload PCAP files, create job
//	GET    /api/jobs                          List all jobs
//	GET    /api/jobs/{id}                     Get job details
//	DELETE /api/jobs/{id}                     Delete job
//
// IMSI Operations:
//
//	GET    /api/jobs/{id}/imsis               Scan and return IMSI list
//	GET    /api/jobs/{id}/imsis/stream        SSE stream for real-time IMSI updates
//
// Export Operations:
//
//	POST   /api/jobs/{id}/export              Export filtered packets (async)
//	GET    /api/jobs/{id}/export/{taskId}/status  Get export task status
//	GET    /api/jobs/{id}/download/{filename} Download exported file
//	POST   /api/jobs/{id}/export/text         Export packets as JSON text
//	POST   /api/jobs/{id}/export/text/download Download packets as JSON
//
// Flow Analysis:
//
//	POST   /api/jobs/{id}/flow/brief          Get brief flow summary
//	POST   /api/jobs/{id}/flow/generate       Generate Mermaid flow diagram
//	POST   /api/jobs/{id}/flow/generate/stream SSE stream for flow generation
//
// # Runtime Dependencies
//
// This package requires the following tools to be installed:
//
//   - tshark (packet analysis)
//   - mergecap (PCAP merging)
//
// Install on Ubuntu/Debian:
//
//	apt install wireshark-cli
//
// Install on macOS:
//
//	brew install wireshark
//
// # IP to Network Element Mapping
//
// Flow diagram generation automatically infers IP→Network Element (NE) mappings
// based on protocol-specific rules:
//
//   - NGAP: SCTP port 38412 → one side is AMF, other is gNB
//   - S1AP: SCTP port 36412 → one side is MME, other is eNB
//   - PFCP: UDP port 8805 → one side is SMF, other is UPF
//   - GTPv2-C: UDP port 2123 → SGW/PGW (direction-based)
//   - GTP-U: UDP port 2152 → based on known endpoints from other protocols
//
// # Configuration
//
// See [uepcap.Config] for all available configuration options.
package httpapi

