package tty

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
)

const playbackTestName = "deploy.fixture:22_2026-11-07_00-00-00.ttyrec.gz"

func TestPlaybackInvalidRequestsReturnErrors(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	defer config.ResetForTesting()
	cfg := config.DefaultConfig()
	cfg.Paths.TtyrecDir = t.TempDir()
	config.SetForTesting(cfg)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}

	tests := []struct {
		name         string
		args         []string
		wantError    string
		wantNotExist bool
	}{
		{name: "missing file", args: nil, wantError: "recording file is required"},
		{name: "invalid filename", args: []string{"--file", "../recording.ttyrec.gz"}, wantError: "invalid recording filename"},
		{name: "recording not found", args: []string{"--file", playbackTestName}, wantError: "could not be found", wantNotExist: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Play(nil, &user, tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Play error = %v, want %q", err, tt.wantError)
			}
			if tt.wantNotExist && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("Play error = %v, want os.ErrNotExist", err)
			}
		})
	}
}

func TestPlaybackEarlyExitReleasesDecompressor(t *testing.T) {
	for _, tt := range []struct {
		name       string
		playScript string
		wantCancel bool
	}{
		{name: "playback failure", playScript: "#!/bin/sh\nexit 23\n"},
		{name: "playback killed", playScript: "#!/bin/sh\nkill -KILL $$\n", wantCancel: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recordingDir := t.TempDir()
			path := filepath.Join(recordingDir, "alice", "fixture")
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, playbackTestName), []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			bin := t.TempDir()
			for name, script := range map[string]string{
				"zcat":    "#!/bin/sh\nexec head -c 16777216 /dev/zero\n",
				"ttyplay": tt.playScript,
			} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}

			// Run the regression in its own process group. If playback hangs, the
			// deadline kills both the test process and its decompressor.
			cmd := exec.Command(os.Args[0], "-test.run=^TestPlaybackEarlyExitSubprocess$")
			cmd.Env = append(os.Environ(),
				"GOB_TTY_PLAY_SUBPROCESS=1",
				"GOB_TTY_PLAY_DIR="+recordingDir,
				fmt.Sprintf("GOB_TTY_PLAY_CANCEL=%t", tt.wantCancel),
				"PATH="+bin+":"+os.Getenv("PATH"),
			)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("playback subprocess failed: %v\n%s", err, output.String())
				}
			case <-timer.C:
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				waitErr := <-done
				t.Fatalf("playback subprocess hung after ttyplay exited (forced stop: %v)\n%s", waitErr, output.String())
			}
		})
	}
}

func TestPlaybackEarlyExitSubprocess(t *testing.T) {
	if os.Getenv("GOB_TTY_PLAY_SUBPROCESS") != "1" {
		return
	}
	config.ResetForTesting()
	_ = config.Load()
	defer config.ResetForTesting()
	cfg := config.DefaultConfig()
	cfg.Paths.TtyrecDir = os.Getenv("GOB_TTY_PLAY_DIR")
	config.SetForTesting(cfg)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	err := Play(nil, &user, []string{"--file", playbackTestName})
	if os.Getenv("GOB_TTY_PLAY_CANCEL") == "true" {
		if err != nil {
			t.Fatalf("intentional playback cancellation returned an error: %v", err)
		}
		return
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
		t.Fatalf("want ttyplay exit status 23 as primary error, got %v", err)
	}
	if strings.Contains(err.Error(), "decompression") {
		t.Fatalf("decompression error replaced playback error: %v", err)
	}
}
