package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLog writes structured JSONL audit records.
type AuditLog struct {
	path string
	mu   sync.Mutex
}

func NewAuditLog(dir string) (*AuditLog, error) {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, err
	}
	return &AuditLog{path: filepath.Join(dir, "audit.jsonl")}, nil
}

type AuditRecord struct {
	Timestamp time.Time              `json:"ts"`
	Action    string                 `json:"action"`
	Source    string                 `json:"src"`
	Result    string                 `json:"result"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

func (a *AuditLog) Write(action, source, result string, details map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	rec := AuditRecord{
		Timestamp: time.Now().UTC(),
		Action:    action,
		Source:    source,
		Result:    result,
		Details:   details,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, string(data))
	return err
}
