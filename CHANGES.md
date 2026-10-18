0.2.10 - 2026-10-18
  - Config validation: sandbox_mode, network_mode, mcp_transport, openclaw_path
  - Reject invalid configs early with descriptive errors

0.2.9 - 2026-10-18
  - Auto-update checker: query GitHub latest release + version compare
  - internal/updater with timeout-safe HTTP client

0.2.8 - 2026-10-18
  - Structured JSONL audit log (internal/audit.go)
  - race-safe append-only audit records with timestamps

0.2.7 - 2026-10-18
  - Token-bucket rate limiter for SSE endpoints (60/min default)
  - race-safe internal/ratelimit with burst support

0.2.6 - 2026-10-18
  - Enhanced health checks: JSON /health /ready endpoints, /metrics stub
  - IsSandboxHealthy returns structured status with uptime estimate

0.2.5 - 2026-10-18
  - SafePath symlink hardening: EvalSymlinks + re-validation prevents symlink escapes
  - Add symlink traversal pen-test cases

0.2.4 - 2026-10-18
  - Build-time version injection via -ldflags (Version/Commit/BuildTime)
  - Fix MCP serverInfo hardcoded version to use pkg/version dynamically
  - Add build script with ldflags support

0.2.3 - 2026-10-18
  - Patch version bump
