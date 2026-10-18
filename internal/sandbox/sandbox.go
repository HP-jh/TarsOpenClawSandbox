package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Manager orchestrates sandbox lifecycle.
type Manager struct {
	Mode   string
	OCPath string
	start  time.Time
}

func NewManager(mode, ocPath string) *Manager {
	return &Manager{Mode: mode, OCPath: ocPath, start: time.Now()}
}

func (m *Manager) Up(ctx context.Context) error {
	switch m.Mode {
	case "gvisor":
		return m.upGVisor(ctx)
	case "firecracker":
		return m.upFirecracker(ctx)
	default:
		return m.upDockerCompat(ctx)
	}
}

func (m *Manager) Down(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "stop", "tarsclaw-sandbox")
	cmd.Run()
	cmd = exec.CommandContext(ctx, "docker", "rm", "-f", "tarsclaw-sandbox")
	return cmd.Run()
}

func (m *Manager) upDockerCompat(ctx context.Context) error {
	seccompPath := filepath.Join(os.TempDir(), "tarsclaw-seccomp.json")
	if err := os.WriteFile(seccompPath, []byte(defaultSeccompProfile()), 0644); err != nil {
		return err
	}
	args := []string{
		"run", "-d", "--name", "tarsclaw-sandbox",
		"--security-opt", "seccomp=" + seccompPath,
		"--security-opt", "apparmor=docker-default",
		"--network", "host",
		"--read-only",
		"--tmpfs", "/tmp:noexec,nosuid,size=100m",
		"-v", m.OCPath + ":/bin/openclaw:ro",
	}
	args = append(args, "alpine:latest", "sh", "-c", "echo 'Sandbox ready'; /bin/openclaw || true; sleep 3600")
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker run failed: %w\n%s", err, string(out))
	}
	m.start = time.Now()
	return nil
}

func (m *Manager) upGVisor(ctx context.Context) error {
	if _, err := exec.LookPath("runsc"); err != nil {
		return fmt.Errorf("gVisor runsc not found. Install: https://gvisor.dev/docs/user_guide/install/")
	}
	seccompPath := filepath.Join(os.TempDir(), "tarsclaw-seccomp.json")
	os.WriteFile(seccompPath, []byte(defaultSeccompProfile()), 0644)
	args := []string{
		"run", "-d", "--name", "tarsclaw-sandbox",
		"--runtime=runsc",
		"--security-opt", "seccomp=" + seccompPath,
		"--network", "host",
		"--read-only",
		"--tmpfs", "/tmp:noexec,nosuid,size=100m",
		"-v", m.OCPath + ":/bin/openclaw:ro",
		"alpine:latest", "sh", "-c", "echo 'gVisor sandbox ready'; sleep 3600",
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gVisor run failed: %w\n%s", err, string(out))
	}
	m.start = time.Now()
	return nil
}

func (m *Manager) upFirecracker(ctx context.Context) error {
	return fmt.Errorf("firecracker mode is planned for v0.2.0. Current mode: %s", m.Mode)
}

func defaultSeccompProfile() string {
	return `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {"names":["accept","accept4","bind","clone","close","connect","epoll_create","epoll_create1","epoll_ctl","epoll_pwait","epoll_wait","eventfd","eventfd2","exit","exit_group","fcntl","fstat","fstatfs","fsync","ftruncate","getdents","getdents64","getegid","geteuid","getgid","getpeername","getpgrp","getpid","getppid","getrandom","getrlimit","getsockname","getsockopt","gettid","getuid","ioctl","kill","listen","lseek","madvise","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlockall","mmap","mprotect","mremap","munlock","munlockall","munmap","nanosleep","open","openat","pause","pipe","pipe2","poll","pread64","pselect6","pwrite64","read","readahead","readlink","readlinkat","recvfrom","recvmmsg","recvmsg","rename","renameat","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_tgsigqueueinfo","sched_getaffinity","sched_yield","sendfile","sendmmsg","sendmsg","sendto","setitimer","setrlimit","setsockopt","shutdown","sigaltstack","socket","socketpair","splice","stat","statfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_settime","tkill","truncate","umask","uname","unlink","unlinkat","utime","utimensat","utimes","wait4","waitid","write","writev"],"action":"SCMP_ACT_ALLOW"}
  ]
}`
}

// SandboxStatus holds structured health information.
type SandboxStatus struct {
	Healthy bool          `json:"healthy"`
	Uptime  time.Duration `json:"uptime"`
	Mode    string        `json:"mode"`
}

func (m *Manager) Status() SandboxStatus {
	return SandboxStatus{
		Healthy: IsSandboxHealthy(),
		Uptime:  time.Since(m.start),
		Mode:    m.Mode,
	}
}

func IsSandboxHealthy() bool {
	out, err := exec.Command("docker", "ps", "--filter", "name=tarsclaw-sandbox", "--format", "{{.Names}}").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "tarsclaw-sandbox")
}
