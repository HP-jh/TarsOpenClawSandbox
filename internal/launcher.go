package internal

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// OpenClawLauncher detects OpenClaw installation and prepares sandbox wrapper.
type OpenClawLauncher struct {
	OpenClawPath string
	Found        bool
}

var commonPaths = []string{
	"openclaw",
	"openclaw-server",
	"/usr/local/bin/openclaw",
	"/usr/bin/openclaw",
	"/opt/openclaw/bin/openclaw",
	"C:\\Program Files\\OpenClaw\\openclaw.exe",
}

func NewLauncher() *OpenClawLauncher {
	l := &OpenClawLauncher{}
	l.detect()
	return l
}

func (l *OpenClawLauncher) detect() {
	for _, p := range commonPaths {
		if runtime.GOOS == "windows" {
			p = strings.ReplaceAll(p, "/", "\\")
		}
		if _, err := exec.LookPath(filepath.Base(p)); err == nil {
			l.OpenClawPath = p
			l.Found = true
			return
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			l.OpenClawPath = p
			l.Found = true
			return
		}
	}
}

func (l *OpenClawLauncher) Validate() error {
	if !l.Found {
		return fmt.Errorf("OpenClaw not found. Install it first:\n" +
			"  curl -fsSL https://get.openclaw.io | sh\n" +
			"Or specify path: tarsclaw-sandbox up --openclaw /path/to/openclaw")
	}
	return nil
}

func (l *OpenClawLauncher) WrapCommand(sandboxArgs []string) *exec.Cmd {
	args := append([]string{"run", "--rm", "-it"}, sandboxArgs...)
	args = append(args, l.OpenClawPath)
	return exec.Command("docker", args...)
}
