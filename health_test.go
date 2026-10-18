package main

import (
	"testing"

	"github.com/HP-jh/TarsOpenClawSandbox/internal/sandbox"
)

func TestSandboxStatusStructure(t *testing.T) {
	m := sandbox.NewManager("docker-compat", "/bin/openclaw")
	st := m.Status()
	if st.Mode != "docker-compat" {
		t.Fatalf("expected mode docker-compat, got %q", st.Mode)
	}
	// Uptime should be >= 0.
	if st.Uptime < 0 {
		t.Fatal("uptime must be non-negative")
	}
}

func TestIsSandboxHealthyNoPanic(t *testing.T) {
	// Docker may not be running; just ensure no panic.
	_ = sandbox.IsSandboxHealthy()
}
