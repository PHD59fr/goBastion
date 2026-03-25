package validation_test

import (
	"testing"

	"goBastion/internal/utils/validation"
)

func TestIsValidHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"my-server.internal", true},
		{"192.168.1.1", true},
		{"[::1]", true},
		{"server_name", true},
		{"", false},
		{"host with space", false},
		{"host@domain", false},
		{"host/path", false},
		{"host\\path", false},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			got := validation.IsValidHost(tc.host)
			if got != tc.want {
				t.Errorf("IsValidHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}

func TestIsValidProtocol(t *testing.T) {
	valid := []string{"ssh", "scpupload", "scpdownload", "sftp", "rsync"}
	invalid := []string{"http", "ftp", "telnet", "", "SSH", "SCP"}

	for _, p := range valid {
		if !validation.IsValidProtocol(p) {
			t.Errorf("IsValidProtocol(%q) = false, want true", p)
		}
	}
	for _, p := range invalid {
		if validation.IsValidProtocol(p) {
			t.Errorf("IsValidProtocol(%q) = true, want false", p)
		}
	}
}
