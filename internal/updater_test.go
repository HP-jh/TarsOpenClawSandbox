package internal

import (
	"testing"
)

func TestCompareVersions(t *testing.T) {
	if !CompareVersions("0.2.8", "v0.2.9") {
		t.Fatal("v0.2.9 should be newer than 0.2.8")
	}
	if CompareVersions("0.2.9", "v0.2.9") {
		t.Fatal("same version should not be newer")
	}
	if CompareVersions("0.2.9", "") {
		t.Fatal("empty remote should not be newer")
	}
}

func TestUpdateCheckerNoPanic(t *testing.T) {
	uc := NewUpdateChecker()
	// We won't hit the real network in unit tests; just ensure no panic on construction.
	if uc.client == nil {
		t.Fatal("http client must be set")
	}
}
