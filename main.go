package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/HP-jh/TarsOpenClawSandbox/internal"
	"github.com/HP-jh/TarsOpenClawSandbox/internal/sandbox"
	"github.com/HP-jh/TarsOpenClawSandbox/pkg/version"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "up":
		cmdUp(os.Args[2:])
	case "down":
		cmdDown()
	case "status":
		cmdStatus()
	case "mcp":
		cmdMCP(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("tarsclaw-sandbox %s (commit %s, built %s)\n", version.Version, version.Commit, version.BuildTime)
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `TarsOpenClawSandbox — Secure OpenClaw Runtime
Usage:
  tarsclaw-sandbox up    [--mode docker-compat|gvisor|firecracker] [--openclaw PATH]
  tarsclaw-sandbox down
  tarsclaw-sandbox status
  tarsclaw-sandbox mcp   [--transport stdio|sse]
  tarsclaw-sandbox version

Environment:
  TARSCLAW_MODE      default sandbox mode
  TARSCLAW_CONFIG    path to config.json (default: ~/.config/tarsclaw-sandbox/config.json)
`)
}

func cmdUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	mode := fs.String("mode", envOr("TARSCLAW_MODE", "docker-compat"), "sandbox mode")
	ocPath := fs.String("openclaw", "", "path to openclaw binary")
	fs.Parse(args)

	launcher := internal.NewLauncher()
	if *ocPath != "" {
		launcher.OpenClawPath = *ocPath
		launcher.Found = true
	}
	if err := launcher.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	mgr := sandbox.NewManager(*mode, launcher.OpenClawPath)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fmt.Printf("Starting sandbox (mode=%s, openclaw=%s)...\n", *mode, launcher.OpenClawPath)
	if err := mgr.Up(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Sandbox started successfully.")
}

func cmdDown() {
	mgr := sandbox.NewManager("", "")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mgr.Down(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
	}
	fmt.Println("Sandbox stopped.")
}

func cmdStatus() {
	if sandbox.IsSandboxHealthy() {
		fmt.Println("Status: running")
	} else {
		fmt.Println("Status: not running")
	}
	cfg := loadConfig()
	fmt.Printf("Mode: %s | Network: %s | MCP: %s\n", cfg.SandboxMode, cfg.NetworkMode, cfg.MCPTransport)
	fmt.Println("Defenses:")
	fmt.Printf("  plugin isolation      = %v\n", cfg.PluginIsolation)
	fmt.Printf("  token encryption      = %v\n", cfg.TokenEncryption)
	fmt.Printf("  webhook SSRF block    = %v\n", cfg.WebhookSSRFBlock)
	fmt.Printf("  LLM filter            = %v\n", cfg.LLMFilter)
	fmt.Printf("  OAuth CSRF            = %v\n", cfg.OAuthCSRF)
	fmt.Printf("  IM smuggling block    = %v\n", cfg.IMSmugglingBlock)
	fmt.Printf("  path traversal guard  = %v\n", cfg.PathTraversalGuard)
	fmt.Printf("  WebSocket CSWSH guard = %v\n", cfg.WebSocketCSWSHGuard)
}

func cmdMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	transport := fs.String("transport", "stdio", "MCP transport (stdio or sse)")
	fs.Parse(args)

	cfg := loadConfig()
	cfg.MCPTransport = *transport

	server := internal.NewMCPServer(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "[MCP] transport=%s starting...\n", *transport)
	if err := server.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func loadConfig() *internal.Config {
	path := envOr("TARSCLAW_CONFIG", filepath.Join(os.Getenv("HOME"), ".config", "tarsclaw-sandbox", "config.json"))
	cfg, err := internal.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: config load failed (%v), using defaults\n", err)
		return internal.DefaultConfig()
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
