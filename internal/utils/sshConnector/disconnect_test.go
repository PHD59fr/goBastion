package sshConnector

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"gorm.io/gorm"
)

func TestSSHDisconnectFinishesRecording(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, sig := range []syscall.Signal{syscall.SIGHUP, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			base := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run", "^TestSSHRecordingSignalHelper$")
			cmd.Env = append(os.Environ(), "GOB_RECORDING_SIGNAL_HELPER=supervisor", "GOB_RECORDING_SIGNAL_BASE="+base, "GOB_RECORDING_SIGNAL_EXE="+executable)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			defer func() { _ = cmd.Process.Kill() }()
			ready := filepath.Join(base, "ready")
			for {
				if _, err := os.Stat(ready); err == nil {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("helper stopped early: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("supervisor did not finalize")
			}
			files, err := filepath.Glob(filepath.Join(base, "archive", "alice", "fixture", "*.ttyrec.gz"))
			if err != nil || len(files) != 1 {
				t.Fatalf("missing archive: %v %v", files, err)
			}
			f, err := os.Open(files[0])
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = f.Close() }()
			reader, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reader.Close() }()
			data, err := io.ReadAll(reader)
			if err != nil || string(data) != "before\nafter\n" {
				t.Fatalf("incomplete recording: %q %v", data, err)
			}
		})
	}
}
func TestSSHRecordingSignalHelper(t *testing.T) {
	mode := os.Getenv("GOB_RECORDING_SIGNAL_HELPER")
	if mode == "" {
		return
	}
	base := os.Getenv("GOB_RECORDING_SIGNAL_BASE")
	if mode == "recorder" {
		signals := make(chan os.Signal, 2)
		signal.Notify(signals, syscall.SIGHUP, syscall.SIGTERM)
		defer signal.Stop(signals)
		raw := os.Getenv("GOB_RECORDING_SIGNAL_RAW")
		if err := os.WriteFile(raw, []byte("before\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		<-signals
		f, err := os.OpenFile(raw, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString("after\n")
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	config.ResetForTesting()
	_ = config.Load()
	defer config.ResetForTesting()
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = filepath.Join(base, "home")
	cfg.Paths.TtyrecDir = filepath.Join(base, "archive")
	cfg.TTYRec.Enabled = true
	config.SetForTesting(cfg)
	t.Setenv("HOME", base)
	t.Setenv("GOB_SESSION_ID", "")
	t.Setenv("PATH", base+":"+os.Getenv("PATH"))
	script := `#!/bin/sh
export GOB_RECORDING_SIGNAL_RAW="$2"
export GOB_RECORDING_SIGNAL_HELPER=recorder
exec "$GOB_RECORDING_SIGNAL_EXE" -test.run '^TestSSHRecordingSignalHelper$'
`
	if err := os.WriteFile(filepath.Join(base, "ttyrec"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.KnownHostsEntry{}); err != nil {
		t.Fatal(err)
	}
	u := models.User{Username: "alice", Enabled: true, Role: models.RoleUser}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&models.KnownHostsEntry{UserID: u.ID, Entry: "fixture ssh-ed25519 AAAA"}).Error; err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(cfg.Paths.HomeBaseDir, "alice", ".ssh", "known_hosts")
	if err := os.MkdirAll(filepath.Dir(kh), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kh, nil, 0600); err != nil {
		t.Fatal(err)
	}
	err = SshConnection(db, u, models.AccessRight{Server: "fixture", Username: "deploy", Port: 22, PrivateKey: "fixture"})
	if err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatal(err)
	}
}
