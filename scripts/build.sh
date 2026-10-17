#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-0.1.0}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
BUILDTIME="${BUILDTIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

LDFLAGS="-s -w -X github.com/HP-jh/TarsOpenClawSandbox/pkg/version.Version=$VERSION -X github.com/HP-jh/TarsOpenClawSandbox/pkg/version.Commit=$COMMIT -X github.com/HP-jh/TarsOpenClawSandbox/pkg/version.BuildTime=$BUILDTIME"

OUTDIR="${OUTDIR:-./dist}"
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"

echo "Building TarsOpenClawSandbox v$VERSION ..."

platforms=(
	"linux/amd64"
	"linux/arm64"
	"darwin/amd64"
	"darwin/arm64"
	"windows/amd64"
	"windows/arm64"
	"android/arm64"
)

for plat in "${platforms[@]}"; do
	GOOS=${plat%/*}
	GOARCH=${plat#*/}
	EXT=""
	if [ "$GOOS" = "windows" ]; then
		EXT=".exe"
	fi
	OUT="$OUTDIR/tarsclaw-sandbox-v${VERSION}-${GOOS}-${GOARCH}${EXT}"
	echo "  -> $plat"
	GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$OUT" .
done

cd "$OUTDIR"
sha256sum tarsclaw-sandbox-v* > SHA256SUMS.txt
cd - > /dev/null

echo "Done. Artifacts in $OUTDIR:"
ls -la "$OUTDIR"
