package session

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
)

func TestDisplayWelcomeHonorsSplashAndShowsPreviousLogin(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	user := models.User{Username: "alice", LastLoginAt: time.Date(2026, time.November, 7, 6, 30, 0, 0, time.UTC), LastLoginFrom: "192.0.2.1"}
	for _, enabled := range []bool{true, false} {
		cfg := config.DefaultConfig()
		cfg.Splash.Enabled = enabled
		config.SetForTesting(cfg)
		out := captureSessionStdout(t, func() { displayWelcome(user, welcomeDB) })
		if strings.Contains(out, logo) != enabled {
			t.Fatalf("splash enabled=%t: %q", enabled, out)
		}
		if !strings.Contains(out, "Welcome to goBastion, "+utils.FgYellowB(user.Username)+"!") || !strings.Contains(out, "Last login: Sat Nov 7 06:30:00 2026 from 192.0.2.1") {
			t.Fatalf("welcome or previous login missing: %q", out)
		}
	}
}

func TestDisplaySplash(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)

	tests := []struct {
		name    string
		enabled bool
		want    string
	}{
		{name: "enabled", enabled: true, want: utils.FgYellow(logo) + "\n"},
		{name: "disabled", enabled: false, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Splash.Enabled = tt.enabled
			config.SetForTesting(cfg)

			if got := captureSessionStdout(t, func() { displaySplash(welcomeSSH) }); got != tt.want {
				t.Fatalf("displaySplash() output = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSplashOptionsAreIndependentAndMasterSwitchWins(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	for _, mode := range []welcomeMode{welcomeSSH, welcomeDB, welcomeInteractive} {
		cfg := config.DefaultConfig()
		cfg.Splash.SSHEnabled, cfg.Splash.DBEnabled, cfg.Splash.InteractiveEnabled = false, false, false
		switch mode {
		case welcomeSSH:
			cfg.Splash.SSHEnabled = true
		case welcomeDB:
			cfg.Splash.DBEnabled = true
		case welcomeInteractive:
			cfg.Splash.InteractiveEnabled = true
		}
		config.SetForTesting(cfg)
		for _, other := range []welcomeMode{welcomeSSH, welcomeDB, welcomeInteractive} {
			out := captureSessionStdout(t, func() { displaySplash(other) })
			if (out != "") != (mode == other) {
				t.Fatalf("splash for %v interferes with %v", mode, other)
			}
		}
		cfg.Splash.Enabled = false
		config.SetForTesting(cfg)
		if out := captureSessionStdout(t, func() { displaySplash(mode) }); out != "" {
			t.Fatal("master splash switch ignored")
		}
	}
}

func captureSessionStdout(t *testing.T, fn func()) string {
	t.Helper()

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("open stdout pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe writer: %v", err)
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close stdout pipe reader: %v", err)
	}
	return out.String()
}
