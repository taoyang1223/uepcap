package tshark

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCheckInstalled(t *testing.T) {
	// Test that tshark is installed
	if err := CheckInstalled("tshark"); err != nil {
		t.Skipf("tshark not installed: %v", err)
	}

	// Test that mergecap is installed
	if err := CheckInstalled("mergecap"); err != nil {
		t.Skipf("mergecap not installed: %v", err)
	}

	// Test non-existent command
	if err := CheckInstalled("nonexistent-command-xyz"); err == nil {
		t.Error("expected error for non-existent command")
	}
}

func TestExec(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := Exec(ctx, "echo", "hello")
	if err != nil {
		t.Fatalf("Exec failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}

	if result.Stdout != "hello\n" {
		t.Errorf("expected 'hello\\n', got %q", result.Stdout)
	}
}

func TestExecWithTimeout(t *testing.T) {
	result, err := ExecWithTimeout(5*time.Second, "echo", "test")
	if err != nil {
		t.Fatalf("ExecWithTimeout failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestIsOnlyTsharkNonFatalWarnings(t *testing.T) {
	stderr := `tshark: The file "/tmp/a.pcap" appears to have been cut short in the middle of a packet.`
	if !isOnlyTsharkNonFatalWarnings(stderr) {
		t.Fatalf("expected cut-short warning to be recognized")
	}

	stderr2 := `tshark: The file "/tmp/a.pcap" appears to have been cut short in the middle of a packet.
tshark: The file "/tmp/a.pcap" appears to have been cut short in the middle of a packet.`
	if !isOnlyTsharkNonFatalWarnings(stderr2) {
		t.Fatalf("expected repeated cut-short warnings to be recognized")
	}

	stderr3 := `Running as user "root" and group "root". This could be dangerous.
tshark: The file "/tmp/a.pcap" appears to have been cut short in the middle of a packet.`
	if !isOnlyTsharkNonFatalWarnings(stderr3) {
		t.Fatalf("expected root warning + cut-short warning to be recognized")
	}

	stderr4 := `Running as user "root" and group "root". This could be dangerous.`
	if !isOnlyTsharkNonFatalWarnings(stderr4) {
		t.Fatalf("expected root warning to be recognized")
	}

	stderr5 := `tshark: The file "/tmp/a.pcap" appears to have been cut short in the middle of a packet.
Some other error`
	if isOnlyTsharkNonFatalWarnings(stderr5) {
		t.Fatalf("expected mixed stderr to NOT be treated as only non-fatal warnings")
	}
}

func TestMergecapDropsTruncatedTailPacket(t *testing.T) {
	if err := CheckInstalled("mergecap"); err != nil {
		t.Skipf("mergecap not installed: %v", err)
	}
	if err := CheckInstalled("tshark"); err != nil {
		t.Skipf("tshark not installed: %v", err)
	}

	dir := t.TempDir()
	truncated := filepath.Join(dir, "truncated.pcap")
	good := filepath.Join(dir, "good.pcap")
	writeTestPcap(t, truncated, true)
	writeTestPcap(t, good, false)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	output := filepath.Join(dir, "merged.pcap")
	if err := Mergecap(ctx, output, truncated, good); err != nil {
		t.Fatalf("Mergecap failed: %v", err)
	}

	count, err := TsharkCount(ctx, output, "")
	if err != nil {
		t.Fatalf("TsharkCount failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("merged packet count = %d, want 2", count)
	}
}

func writeTestPcap(t *testing.T, path string, truncatedTail bool) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test pcap: %v", err)
	}
	defer f.Close()

	writeLE := func(v any) {
		t.Helper()
		if err := binary.Write(f, binary.LittleEndian, v); err != nil {
			t.Fatalf("write test pcap: %v", err)
		}
	}

	writeLE(uint32(0xa1b2c3d4)) // byte-swapped on disk by LittleEndian: d4 c3 b2 a1
	writeLE(uint16(2))
	writeLE(uint16(4))
	writeLE(uint32(0))
	writeLE(uint32(0))
	writeLE(uint32(262144))
	writeLE(uint32(1)) // Ethernet

	writePacket := func(ts uint32, inclLen uint32, payload []byte) {
		t.Helper()
		writeLE(ts)
		writeLE(uint32(0))
		writeLE(inclLen)
		writeLE(inclLen)
		if _, err := f.Write(payload); err != nil {
			t.Fatalf("write packet payload: %v", err)
		}
	}

	writePacket(1, 60, make([]byte, 60))
	if truncatedTail {
		writePacket(2, 10, make([]byte, 5))
	}
}
