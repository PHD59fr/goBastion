package system

import (
	"testing"
)

func TestClientIPFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     string
	}{
		{"valid SSH_CLIENT", "192.168.1.1 54321 22", "192.168.1.1"},
		{"empty SSH_CLIENT", "", "unknown"},
		{"single field", "10.0.0.1", "10.0.0.1"},
		{"whitespace only", "   ", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("SSH_CLIENT", tt.envValue)
			got := ClientIPFromEnv()
			if got != tt.want {
				t.Errorf("ClientIPFromEnv() = %q, want %q", got, tt.want)
			}
		})
	}
}
