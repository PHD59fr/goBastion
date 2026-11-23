package sshConnector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"gorm.io/gorm"
)

// The transport deliberately keeps stdout open until it receives SIGHUP. EOF
// therefore proves that abrupt session exit closes the inherited transport,
// rather than merely returning an exit status for the session process.
func TestDirectSSHStopsAfterSessionProcessExit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"unrecorded", "opaque-transfer"} {
		t.Run(mode, func(t *testing.T) {
			base := t.TempDir()
			controlRead, controlWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = controlRead.Close(); _ = controlWrite.Close() }()
			outputRead, outputWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = outputRead.Close(); _ = outputWrite.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestSSHParentDeathHelper$")
			cmd.Env = append(os.Environ(), "GOB_SSH_PARENT_DEATH_HELPER="+mode, "GOB_SSH_PARENT_DEATH_BASE="+base, "GOB_SSH_PARENT_DEATH_EXE="+executable)
			cmd.ExtraFiles = []*os.File{controlRead}
			cmd.Stdout = outputWrite
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			_ = controlRead.Close()
			_ = outputWrite.Close()
			defer func() { _ = cmd.Process.Kill() }()
			// A failing regression must also clean up the orphan it detects.
			defer func() {
				data, err := os.ReadFile(filepath.Join(base, "transport.pid"))
				if err == nil {
					pid, err := strconv.Atoi(string(data))
					if err == nil {
						command, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
						if err == nil && bytes.Contains(command, []byte(base)) {
							_ = syscall.Kill(pid, syscall.SIGKILL)
						}
					}
				}
			}()
			outputDone := make(chan error, 1)
			go func() { _, err := io.Copy(io.Discard, outputRead); outputDone <- err }()
			parentDone := make(chan error, 1)
			go func() { parentDone <- cmd.Wait() }()
			for {
				if _, err := os.Stat(filepath.Join(base, "transport.ready")); err == nil {
					break
				}
				select {
				case err := <-parentDone:
					t.Fatalf("session helper exited before transport started: %v", err)
				case <-ctx.Done():
					t.Fatal("transport did not start")
				case <-time.After(10 * time.Millisecond):
				}
			}
			if _, err := controlWrite.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-parentDone:
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
					t.Fatalf("session helper exit = %v, want abrupt exit 23", err)
				}
			case <-ctx.Done():
				t.Fatal("session helper did not exit")
			}
			select {
			case err := <-outputDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("SSH transport retained stdout after session process exited")
			}
			if _, err := os.Stat(filepath.Join(base, "transport.stopped")); err != nil {
				t.Fatal("SSH transport did not receive parent-death SIGHUP")
			}
		})
	}
}

func TestSSHParentDeathHelper(t *testing.T) {
	mode := os.Getenv("GOB_SSH_PARENT_DEATH_HELPER")
	if mode == "" {
		return
	}
	base := os.Getenv("GOB_SSH_PARENT_DEATH_BASE")
	if mode == "transport" {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGHUP)
		defer signal.Stop(signals)
		if err := os.WriteFile(filepath.Join(base, "transport.pid"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "transport.ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		<-signals
		if err := os.WriteFile(filepath.Join(base, "transport.stopped"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	config.ResetForTesting()
	_ = config.Load()
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = filepath.Join(base, "home")
	cfg.TTYRec.Enabled = mode == "opaque-transfer"
	config.SetForTesting(cfg)
	t.Setenv("HOME", base)
	t.Setenv("PATH", base+":"+os.Getenv("PATH"))
	script := `#!/bin/sh
export GOB_SSH_PARENT_DEATH_HELPER=transport
exec "$GOB_SSH_PARENT_DEATH_EXE" -test.run=^TestSSHParentDeathHelper$ -- "$GOB_SSH_PARENT_DEATH_BASE"
`
	if err := os.WriteFile(filepath.Join(base, "ssh"), []byte(script), 0700); err != nil {
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
	go func() {
		control := os.NewFile(3, "parent-death-control")
		var value [1]byte
		if _, err := control.Read(value[:]); err != nil {
			os.Exit(24)
		}
		os.Exit(23)
	}()
	access := models.AccessRight{Server: "fixture", Username: "deploy", Port: 22, PrivateKey: "fixture"}
	if mode == "opaque-transfer" {
		access.RemoteCmd = "scp -t /fixture"
	}
	if err := SshConnection(db, u, access); err != nil {
		t.Fatal(err)
	}
	t.Fatal("SSH transport returned before the session process exited")
}
