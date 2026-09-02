package session

import (
	"fmt"
	"os"
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

func TestInteractiveAllowConfig(t *testing.T) {
	config.ResetForTesting()
	t.Cleanup(config.ResetForTesting)
	cfg := config.Load()
	if !cfg.Interactive.Allow {
		t.Fatal("interactive.allow should default to true")
	}
	cfg.Interactive.Allow = false
	if cfg.Interactive.Allow {
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
