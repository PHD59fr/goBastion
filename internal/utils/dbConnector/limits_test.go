package dbConnector

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
)

func TestDBIdleTimeoutStopsClientAndPreservesRecording(t *testing.T) {
	for _, record := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "recorded"}[record], func(t *testing.T) {
			config.ResetForTesting()
			_ = config.Load()
			t.Cleanup(config.ResetForTesting)
			base := t.TempDir()
			cfg := config.DefaultConfig()
			cfg.TTYRec.Enabled = record
			cfg.Paths.TtyrecDir = filepath.Join(base, "recordings")
			if err := os.Mkdir(cfg.Paths.TtyrecDir, 0700); err != nil {
				t.Fatal(err)
			}
			cfg.Session.IdleTimeout = config.Duration(150 * time.Millisecond)
			config.SetForTesting(cfg)
			previous := sandboxCommand
			t.Cleanup(func() { sandboxCommand = previous })
			sandboxCommand = func(ctx context.Context, _ string, _ int64, _ string, _, _ []string) (*exec.Cmd, func(), error) {
				cmd := exec.CommandContext(ctx, "/bin/sleep", "10")
				cmd.Env = os.Environ()
				return cmd, func() {}, nil
			}
			if record {
				// Model a recorder that creates output, then execs its child.
				script := "#!/bin/sh\nprintf 'RECORDED_BEFORE_IDLE_TIMEOUT' > \"$2\"\nshift 3\nexec \"$@\"\n"
				if err := os.WriteFile(filepath.Join(base, "ttyrec"), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				t.Setenv("PATH", base+":"+os.Getenv("PATH"))
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := ConnectContext(ctx, nil, models.User{Username: "audit"}, models.DBAccessRight{Host: "fixture", Username: "reader", Port: 3306, Protocol: "mysql"})
			if err == nil || !strings.Contains(err.Error(), "idle timeout reached") || ctx.Err() != nil {
				t.Fatalf("idle timeout was not enforced promptly: %v, outer context=%v", err, ctx.Err())
			}
			if record {
				files, err := filepath.Glob(filepath.Join(cfg.Paths.TtyrecDir, "audit", "fixture", "*.ttyrec.gz"))
				if err != nil || len(files) != 1 {
					t.Fatalf("recording was not published: %v %v", files, err)
				}
				f, err := os.Open(files[0])
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()
				gz, err := gzip.NewReader(f)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = gz.Close() }()
				data, err := io.ReadAll(gz)
				if err != nil || string(data) != "RECORDED_BEFORE_IDLE_TIMEOUT" {
					t.Fatalf("incomplete recording: %q %v", data, err)
				}
			}
		})
	}
}
