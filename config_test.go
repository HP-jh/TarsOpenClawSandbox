package main

import (
	"testing"

	"github.com/HP-jh/TarsOpenClawSandbox/internal"
)

func TestConfigValidateDefaults(t *testing.T) {
	cfg := internal.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestConfigValidateInvalidMode(t *testing.T) {
	cfg := internal.DefaultConfig()
	cfg.SandboxMode = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid sandbox_mode should fail validation")
	}
}

func TestConfigValidateInvalidTransport(t *testing.T) {
	cfg := internal.DefaultConfig()
	cfg.MCPTransport = "grpc"
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid mcp_transport should fail validation")
	}
}
