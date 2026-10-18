package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds sandbox runtime configuration.
type Config struct {
	OpenClawPath string `json:"openclaw_path,omitempty"`
	SandboxMode  string `json:"sandbox_mode"` // docker-compat, gvisor, firecracker
	NetworkMode  string `json:"network_mode"` // loopback, tailscale, wireguard
	SeccompProfile string `json:"seccomp_profile,omitempty"`
	PluginIsolation bool `json:"plugin_isolation"`
	TokenEncryption   bool `json:"token_encryption"`
	WebhookSSRFBlock  bool `json:"webhook_ssrf_block"`
	LLMFilter         bool `json:"llm_filter"`
	OAuthCSRF         bool `json:"oauth_csrf"`
	IMSmugglingBlock  bool `json:"im_smuggling_block"`
	PathTraversalGuard bool `json:"path_traversal_guard"`
	WebSocketCSWSHGuard bool `json:"websocket_cswsh_guard"`
	MCPTransport       string `json:"mcp_transport"` // stdio, sse
}

func DefaultConfig() *Config {
	return &Config{
		SandboxMode:          "docker-compat",
		NetworkMode:          "loopback",
		SeccompProfile:       "default",
		PluginIsolation:      true,
		TokenEncryption:      true,
		WebhookSSRFBlock:     true,
		LLMFilter:            true,
		OAuthCSRF:            true,
		IMSmugglingBlock:     true,
		PathTraversalGuard:   true,
		WebSocketCSWSHGuard:  true,
		MCPTransport:         "stdio",
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Validate checks config fields for correctness.
func (c *Config) Validate() error {
	validModes := map[string]bool{"docker-compat": true, "gvisor": true, "firecracker": true}
	if !validModes[c.SandboxMode] {
		return fmt.Errorf("invalid sandbox_mode: %q", c.SandboxMode)
	}
	validNetworks := map[string]bool{"loopback": true, "tailscale": true, "wireguard": true}
	if !validNetworks[c.NetworkMode] {
		return fmt.Errorf("invalid network_mode: %q", c.NetworkMode)
	}
	validTransports := map[string]bool{"stdio": true, "sse": true}
	if !validTransports[c.MCPTransport] {
		return fmt.Errorf("invalid mcp_transport: %q", c.MCPTransport)
	}
	if c.OpenClawPath != "" {
		if _, err := os.Stat(c.OpenClawPath); err != nil {
			return fmt.Errorf("openclaw_path not found: %w", err)
		}
	}
	return nil
}
