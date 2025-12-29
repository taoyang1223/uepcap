// Package uepcap provides a Go SDK for analyzing PCAP files containing mobile network signaling.
//
// It supports extracting IMSIs, resolving protocol filters (NGAP, PFCP, S1AP, GTPv2, GTP-U),
// exporting filtered packets, and generating signaling flow diagrams.
//
// # Runtime Dependencies
//
// This package requires tshark and mergecap (from Wireshark) to be installed and available in PATH.
// Install via: apt install wireshark-cli (or brew install wireshark on macOS).
//
// # Quick Start
//
// For HTTP API integration, see the httpapi subpackage.
// For programmatic use:
//
//	app, err := uepcap.New(uepcap.Config{
//	    DataDir: "./data",
//	    JobTTL:  time.Hour,
//	    MaxJobs: 3,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	app.Start(ctx)
//
//	// Use programmatic APIs
//	imsis, _ := app.ScanIMSIs(ctx, "path/to/file.pcap")
package uepcap

import (
	"context"
	"fmt"
	"time"

	"gitee.com/yangdadayyds/uepcap/internal/api"
	"gitee.com/yangdadayyds/uepcap/internal/job"
	"gitee.com/yangdadayyds/uepcap/internal/protocol"
	"gitee.com/yangdadayyds/uepcap/internal/tshark"
)

// Config holds configuration for the uepcap application.
type Config struct {
	// DataDir is the directory for storing temporary job data.
	// Default: "./data"
	DataDir string

	// JobTTL is the time-to-live for jobs before automatic cleanup.
	// Default: 1 hour
	JobTTL time.Duration

	// MaxJobs is the maximum number of jobs to keep (0 = unlimited).
	// When exceeded, oldest jobs are automatically removed.
	// Default: 3
	MaxJobs int

	// CleanupInterval is how often the cleanup routine runs.
	// Default: 5 minutes
	CleanupInterval time.Duration

	// TsharkPath is the path to tshark binary.
	// Default: "tshark" (uses PATH)
	TsharkPath string

	// MergecapPath is the path to mergecap binary.
	// Default: "mergecap" (uses PATH)
	MergecapPath string

	// SkipDependencyCheck skips validation of tshark/mergecap at startup.
	// Useful for testing or when dependencies are guaranteed to exist.
	SkipDependencyCheck bool

	// Moonshot configuration for LLM-powered flow annotations (optional).
	// If not set, environment variables MOONSHOT_API_KEY, MOONSHOT_BASE_URL,
	// and MOONSHOT_MODEL are used.
	Moonshot *MoonshotConfig
}

// MoonshotConfig holds configuration for the Moonshot LLM API.
type MoonshotConfig struct {
	APIKey  string
	BaseURL string // Default: "https://api.moonshot.cn/v1"
	Model   string // Default: server default
}

// applyDefaults fills in default values for unset config fields.
func (c *Config) applyDefaults() {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.JobTTL == 0 {
		c.JobTTL = time.Hour
	}
	if c.MaxJobs == 0 {
		c.MaxJobs = 3
	}
	if c.CleanupInterval == 0 {
		c.CleanupInterval = 5 * time.Minute
	}
	if c.TsharkPath == "" {
		c.TsharkPath = "tshark"
	}
	if c.MergecapPath == "" {
		c.MergecapPath = "mergecap"
	}
}

// App is the main uepcap application instance.
// It manages job lifecycle, provides programmatic APIs, and can be used
// to register HTTP handlers via the httpapi package.
type App struct {
	config  Config
	jobMgr  *job.Manager
	handler *api.Handler

	// For cleanup goroutine management
	cleanupCancel context.CancelFunc
}

// New creates a new uepcap App with the given configuration.
// It validates runtime dependencies (tshark, mergecap) unless SkipDependencyCheck is set.
func New(cfg Config) (*App, error) {
	cfg.applyDefaults()

	// Check dependencies
	if !cfg.SkipDependencyCheck {
		if err := tshark.CheckInstalled(cfg.TsharkPath); err != nil {
			return nil, fmt.Errorf("tshark not found at %q: %w (install wireshark-cli or wireshark)", cfg.TsharkPath, err)
		}
		if err := tshark.CheckInstalled(cfg.MergecapPath); err != nil {
			return nil, fmt.Errorf("mergecap not found at %q: %w (install wireshark-cli or wireshark)", cfg.MergecapPath, err)
		}
	}

	// Initialize job manager
	jobMgr := job.NewManagerWithLimit(cfg.DataDir, cfg.JobTTL, cfg.MaxJobs)

	// Initialize API handler
	handler := api.NewHandler(jobMgr)

	return &App{
		config:  cfg,
		jobMgr:  jobMgr,
		handler: handler,
	}, nil
}

// Start begins background cleanup routines.
// This should be called after creating the App and before processing requests.
// The cleanup will run until the provided context is cancelled.
func (a *App) Start(ctx context.Context) {
	// Create a child context for cleanup that we can cancel independently
	cleanupCtx, cancel := context.WithCancel(ctx)
	a.cleanupCancel = cancel

	go a.jobMgr.StartCleanup(cleanupCtx, a.config.CleanupInterval)
}

// Stop cancels background cleanup routines.
// This is automatically called if the context passed to Start is cancelled.
func (a *App) Stop() {
	if a.cleanupCancel != nil {
		a.cleanupCancel()
	}
}

// Config returns the current configuration (read-only).
func (a *App) Config() Config {
	return a.config
}

// JobManager returns the internal job manager.
// This is primarily for internal use by the httpapi package.
func (a *App) JobManager() *job.Manager {
	return a.jobMgr
}

// Handler returns the internal API handler.
// This is primarily for internal use by the httpapi package.
func (a *App) Handler() *api.Handler {
	return a.handler
}

// =============================================================================
// Programmatic SDK APIs
// =============================================================================

// ScanIMSIs scans a PCAP file and returns all unique IMSI values found.
// The scan uses multiple strategies in parallel for comprehensive extraction.
func (a *App) ScanIMSIs(ctx context.Context, pcapPath string) ([]string, error) {
	scanner := protocol.NewIMSIScanner()
	return scanner.ScanIMSIs(ctx, pcapPath)
}

// ResolveFilters resolves display filters for an IMSI across specified protocols.
// Returns:
//   - filtersByProto: map of protocol name to its display filter
//   - combinedFilter: OR-combined filter for all protocols
//   - error: if resolution fails
//
// Supported protocols: ngap, pfcp, s1ap, gtpv2, gtpu, ueip
func (a *App) ResolveFilters(ctx context.Context, pcapPath, imsi string, protocols []string) (filtersByProto map[string]string, combinedFilter string, err error) {
	resolver := protocol.NewFilterResolver()
	return resolver.ResolveFilters(ctx, pcapPath, imsi, protocols)
}

// ResolveFilter resolves a combined display filter for an IMSI.
// This is a convenience wrapper around ResolveFilters that only returns the combined filter.
func (a *App) ResolveFilter(ctx context.Context, pcapPath, imsi string, protocols []string) (string, error) {
	resolver := protocol.NewFilterResolver()
	return resolver.ResolveFilter(ctx, pcapPath, imsi, protocols)
}

// ExportPackets exports packets matching a filter from source pcap to destination.
func (a *App) ExportPackets(ctx context.Context, srcPcap, dstPcap, filter string) error {
	return tshark.TsharkExport(ctx, srcPcap, dstPcap, filter)
}

// MergePcaps merges multiple PCAP files into a single output file.
func (a *App) MergePcaps(ctx context.Context, outputPcap string, inputPcaps ...string) error {
	return tshark.Mergecap(ctx, outputPcap, inputPcaps...)
}

// CheckDependencies verifies that tshark and mergecap are available.
// This is called automatically by New() unless SkipDependencyCheck is set.
func CheckDependencies() error {
	if err := tshark.CheckInstalled("tshark"); err != nil {
		return fmt.Errorf("tshark not found: %w (install wireshark-cli or wireshark)", err)
	}
	if err := tshark.CheckInstalled("mergecap"); err != nil {
		return fmt.Errorf("mergecap not found: %w (install wireshark-cli or wireshark)", err)
	}
	return nil
}

