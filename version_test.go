package main

import (
	"testing"

	"github.com/HP-jh/TarsOpenClawSandbox/pkg/version"
)

func TestVersionNotEmpty(t *testing.T) {
	if version.Version == "" {
		t.Fatal("Version must not be empty")
	}
	if version.Version == "dev" {
		t.Log("Version is dev (unbuilt binary)")
	}
}

func TestVersionFormat(t *testing.T) {
	// Expect semantic-like version e.g. 0.2.4
	if len(version.Version) < 3 {
		t.Fatalf("Version looks too short: %q", version.Version)
	}
}
