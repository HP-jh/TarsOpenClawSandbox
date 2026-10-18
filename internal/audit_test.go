package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditLogWriteAndRead(t *testing.T) {
	dir := t.TempDir()
	al, err := NewAuditLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := al.Write("defend", "test", "pass", map[string]interface{}{"rule": "ssrf"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "defend") {
		t.Fatal("audit log should contain action")
	}
	if !strings.Contains(string(data), "ssrf") {
		t.Fatal("audit log should contain details")
	}
}
