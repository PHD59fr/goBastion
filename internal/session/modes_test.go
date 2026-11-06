package session

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"
)

func TestCaptureOutputDoesNotLeakFileDescriptors(t *testing.T) {
	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skipf("file descriptor inspection is unavailable: %v", err)
		}
		return len(entries)
	}

	before := countFDs()
	for i := 0; i < 20; i++ {
		stdout, stderr, runErr, captureErr := captureOutput(func() error {
			_, _ = fmt.Fprint(os.Stdout, "stdout")
			_, _ = fmt.Fprint(os.Stderr, "stderr")
			return nil
		})
		if runErr != nil || captureErr != nil {
			t.Fatalf("captureOutput errors: run=%v capture=%v", runErr, captureErr)
		}
		if stdout != "stdout" || stderr != "stderr" {
			t.Fatalf("captured stdout=%q stderr=%q", stdout, stderr)
		}
	}
	after := countFDs()
	if after != before {
		t.Fatalf("open file descriptors changed from %d to %d", before, after)
	}
}

func TestParseDBRequest(t *testing.T) {
	tests := []struct {
		name   string
		cmd    string
		args   []string
		want   []string
		wantOK bool
	}{
		{
			name:   "split command string",
			cmd:    "--db db-main.internal --mysql --dbname appdb",
			want:   []string{"db-main.internal", "--mysql", "--dbname", "appdb"},
			wantOK: true,
		},
		{
			name:   "separate args",
			cmd:    "--db",
			args:   []string{"dbuser@db-main.internal"},
			want:   []string{"dbuser@db-main.internal"},
			wantOK: true,
		},
		{
			name:   "short separate args",
			cmd:    "-db",
			args:   []string{"dbuser@db-main.internal"},
			want:   []string{"dbuser@db-main.internal"},
			wantOK: true,
		},
		{
			name:   "short split command string",
			cmd:    "-db db-main.internal --mysql --dbname appdb",
			want:   []string{"db-main.internal", "--mysql", "--dbname", "appdb"},
			wantOK: true,
		},
		{
			name:   "not a db request",
			cmd:    "deploy@host -p 22",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseDBRequest(tt.cmd, tt.args)
			if ok != tt.wantOK {
				t.Fatalf("parseDBRequest(%q, %v) ok = %t, want %t", tt.cmd, tt.args, ok, tt.wantOK)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseDBRequest(%q, %v) = %v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}

func TestInteractiveEnabledConfig(t *testing.T) {
	config.ResetForTesting()
	t.Cleanup(config.ResetForTesting)
	cfg := config.Load()
	if !cfg.Interactive.Enabled {
		t.Fatal("interactive.allow should default to true")
	}
	cfg.Interactive.Enabled = false
	if cfg.Interactive.Enabled {
		t.Fatal("expected interactive.allow to accept runtime override")
	}
}

func TestTCPProxyMFABlockMessage(t *testing.T) {
	config.ResetForTesting()
	t.Cleanup(config.ResetForTesting)
	cfg := config.Load()

	if msg := tcpProxyMFABlockMessage(models.User{}); msg != "" {
		t.Fatalf("unexpected block message without MFA: %q", msg)
	}
	if msg := tcpProxyMFABlockMessage(models.User{PasswordHash: "hash"}); msg == "" {
		t.Fatal("expected password MFA block message")
	}
	if msg := tcpProxyMFABlockMessage(models.User{TOTPEnabled: true, TOTPSecret: "secret"}); msg == "" {
		t.Fatal("expected TOTP MFA block message")
	}

	cfg.RequireMFA.Enabled = true
	if msg := tcpProxyMFABlockMessage(models.User{}); msg == "" {
		t.Fatal("expected global MFA block message")
	}
}

func TestEnrollmentRequestIsExact(t *testing.T) {
	for _, args := range [][]string{{"-osh selfSetupTOTP"}, {"-osh", "selfSetupTOTP"}} {
		if !enrollmentRequest(args) {
			t.Fatalf("valid enrollment rejected: %q", args)
		}
	}
	for _, args := range [][]string{nil, {"--"}, {"-osh selfSetupTOTP extra"}, {"-osh selfSetupTOTP; accountList"}, {"-osh", "accountList"}} {
		if enrollmentRequest(args) {
			t.Fatalf("enrollment exception too broad: %q", args)
		}
	}
}

func TestLocalMoshNeverExecutes(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	if err := os.WriteFile(filepath.Join(dir, "mosh-server"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	cfg := config.DefaultConfig()
	cfg.Mosh.Enabled = true
	_ = config.Load()
	config.SetForTesting(cfg)
	defer config.ResetForTesting()
	for _, command := range []string{"mosh-server", "mosh-server new -s -l LANG=en_US.UTF-8"} {
		runMoshServer(command, []string{"--", "/bin/sh"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("local Mosh executed")
	}
}

func TestMandatoryMFAOnlyAllowsUnenrolledSetup(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RequireMFA.Enabled = true
	_ = config.Load()
	config.SetForTesting(cfg)
	defer config.ResetForTesting()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u := models.User{Enabled: true}
	if !checkMFAForRequest(nil, &u, log, []string{"-osh", "selfSetupTOTP"}) {
		t.Fatal("enrollment blocked")
	}
	for _, args := range [][]string{nil, {"-osh", "accountList"}, {"-osh", "selfSetupTOTP", "extra"}, {"--db", "target"}} {
		if checkMFAForRequest(nil, &u, log, args) {
			t.Fatalf("MFA bypass: %q", args)
		}
	}
	// A pipe is not an authenticated terminal password response.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	_ = w.Close()
	original := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = original }()
	u.PasswordHash = "configured-password-factor"
	if checkMFAForRequest(nil, &u, log, []string{"-osh", "selfSetupTOTP"}) {
		t.Fatal("enrollment bypassed password factor")
	}
}
