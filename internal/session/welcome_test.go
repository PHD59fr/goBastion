package session

import (
	"bytes"
	"io"
	"os"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/utils"
)

func TestDisplaySplash(t *testing.T) {
	config.ResetForTesting()
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

			if got := captureSessionStdout(t, displaySplash); got != tt.want {
				t.Fatalf("displaySplash() output = %q, want %q", got, tt.want)
			}
		})
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
