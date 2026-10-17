# TarsOpenClawSandbox

Secure runtime sandbox for [OpenClaw](https://github.com/openclaw/openclaw) — the multi-channel Gateway covering Discord, Telegram, WhatsApp, iMessage, Feishu, Lark, Slack and more.

## Why

OpenClaw is powerful, but its attack surface is large:

- **258 CVEs** tracked (as of national cyber-security warning 2026-03-13)
- **10.8%** of community plugins are malicious
- **85%** of public instances are exposed to the internet

TarsOpenClawSandbox wraps OpenClaw in a defense-in-depth runtime that cuts those risks without changing OpenClaw itself.

## Quick Start

```bash
# Install
curl -fsSL https://github.com/HP-jh/TarsOpenClawSandbox/releases/latest/download/install.sh | sh

# One-line start
tarsclaw-sandbox up

# Check status
tarsclaw-sandbox status

# Stop
tarsclaw-sandbox down
```

## Vulnerability Coverage (8 Classes)

| # | Threat | Defense | Status |
|---|--------|---------|--------|
| 1 | Plugin namespace hijack | Per-plugin user + netns + cgroup | v0.1.0 |
| 2 | Session token leak | HMAC-SHA256 envelope; key never on disk in plaintext | v0.1.0 |
| 3 | WebSocket CSWSH | Strict Origin validation + mTLS ready | v0.1.0 |
| 4 | File path traversal | `openat2` / `RESOLVE_BENEATH` concept | v0.1.0 |
| 5 | Webhook SSRF | Private / loopback / link-local blacklist + DNS rebind guard | v0.1.0 |
| 6 | LLM prompt injection | Regex filter (re-uses TSG v4.7 WAF + semguard patterns) | v0.1.0 |
| 7 | OAuth state CSRF | State = SHA256(device fingerprint + monotonic counter + secret) | v0.1.0 |
| 8 | IM protocol smuggling | Strict content-type whitelist + length cap + null-byte guard | v0.1.0 |

Every class ships with at least **1 fuzz + 1 pen-test** case in `pen_test.go`.

## Sandbox Stack

| Mode | Isolation Level | Latency | When to Use |
|------|----------------|---------|-------------|
| `docker-compat` (default) | seccomp + AppArmor | Low | Development, quick tests |
| `gvisor` | User-space kernel (runsc) | Medium | Production, untrusted plugins |
| `firecracker` | MicroVM (KVM) | <125 ms boot | Enterprise, multi-tenant |

Switch mode:
```bash
tarsclaw-sandbox up --mode gvisor
```

## MCP Server

TarsOpenClawSandbox exposes itself as an MCP server so TarsSecureGuard can mount it as an external tool.

```bash
# stdio transport (default)
tarsclaw-sandbox mcp

# SSE transport
tarsclaw-sandbox mcp --transport sse
```

Tools exposed:
- `sandbox_up` / `sandbox_down`
- `defender_status`
- `filter_llm`
- `check_ssrf`

To mount in TarsSecureGuard `config.json`:

```json
{
  "mcpServers": {
    "openclaw_sandbox": {
      "command": "tarsclaw-sandbox",
      "args": ["mcp"]
    }
  }
}
```

## Network Modes

- **loopback** (default) — Unix socket only, zero public exposure
- **tailscale** — Encrypted mesh between your devices
- **wireguard** — Manual VPN tunneling

## Building from Source

```bash
git clone https://github.com/HP-jh/TarsOpenClawSandbox.git
cd TarsOpenClawSandbox
./scripts/build.sh
```

Produces 7 platform binaries + `SHA256SUMS.txt` in `./dist/`.

## Test

```bash
go test -race ./...
```

## Roadmap

- v0.1.0 — MVP: gVisor + 8 defenses + MCP stdio/SSE + 7-platform binaries
- v0.2.0 — Firecracker microVM upgrade
- v0.3.0 — Tailscale pairing + multi-device federation
- v0.4.0 — OpenClaw official MCP server interoperability
- v1.0.0 — Full CVE coverage + red-team report

## License

Apache-2.0
