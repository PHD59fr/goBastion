package validation_test

import (
	"strings"
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
		{"2001:db8::1", true},
		{"localhost", true},
		{"server_name", true},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), true},
		{"", false},
		{"---", false},
		{"___", false},
		{"a..b", false},
		{"-server", false},
		{"server-", false},
		{"_server", false},
		{"server_", false},
		{strings.Repeat("a", 64) + ".example", false},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), false},
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

func TestIsValidHostReference_PreservesLegacyRuntimeNames(t *testing.T) {
	for _, host := range []string{"---", "_legacy", "legacy_"} {
		if !validation.IsValidHostReference(host) {
			t.Errorf("IsValidHostReference(%q) = false, want true", host)
		}
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
