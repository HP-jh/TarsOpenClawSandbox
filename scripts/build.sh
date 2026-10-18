#!/usr/bin/env bash
set -euo pipefail

MODULE="github.com/HP-jh/TarsOpenClawSandbox/pkg/version"
VERSION=${VERSION:-$(git describe --tags --always 2>/dev/null || echo 'dev')}
COMMIT=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')}
BUILD_TIME=${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}

LDFLAGS="-X ${MODULE}.Version=${VERSION} -X ${MODULE}.Commit=${COMMIT} -X ${MODULE}.BuildTime=${BUILD_TIME}"

echo "Building tarsclaw-sandbox ${VERSION} (${COMMIT})..."
go build -ldflags "$LDFLAGS" -o tarsclaw-sandbox .
