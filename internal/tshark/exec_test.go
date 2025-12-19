package tshark

import (
	"context"
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
