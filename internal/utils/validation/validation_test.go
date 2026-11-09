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

func TestNormalizeRedisDatabase(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
		ok    bool
	}{
		{"", "", true},
		{"0", "0", true},
		{"2", "2", true},
		{"02", "2", true},
		{"2147483647", "2147483647", true},
		{"-1", "", false},
		{"+2", "2", true},
		{"1.5", "", false},
		{"two", "", false},
		{" 2", "", false},
		{"2147483648", "", false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			got, err := validation.NormalizeRedisDatabase(tc.input)
			if tc.ok && err != nil {
				t.Fatalf("NormalizeRedisDatabase(%q) error = %v", tc.input, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("NormalizeRedisDatabase(%q) accepted invalid input", tc.input)
			}
			if got != tc.want {
				t.Fatalf("NormalizeRedisDatabase(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
