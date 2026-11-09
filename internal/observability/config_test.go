package observability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDisabledConfigurationDoesNotRequireCredentialOrDatabase(t *testing.T) {
	t.Setenv("OBS_ENABLED", "")
	t.Setenv("OBS_AUTH_TOKEN_FILE", "/unreadable/secret")
	config, err := LoadConfigFromEnv()
	if err != nil || config.Enabled {
		t.Fatal("observation service must default to disabled")
	}
	for _, value := range []string{"not-bool", "enabled"} {
		t.Setenv("OBS_ENABLED", value)
		if _, err := LoadConfigFromEnv(); err == nil {
			t.Fatal("invalid enabled setting accepted")
		}
	}
}

func TestObservationConfigurationRejectsUnsafeSettings(t *testing.T) {
	t.Setenv("OBS_ENABLED", "true")
	t.Setenv("OBS_AUTH_TOKEN_FILE", "")
	t.Setenv("OBS_AUTH_TOKEN", "")
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("enabled service accepted missing auth token")
	}
	for _, address := range []string{"0.0.0.0:9090", ":9090", "localhost:9090", "192.0.2.1:9090", "127.0.0.1:0", "[::]:9090"} {
		if err := validateListenAddress(address); err == nil {
			t.Fatalf("unsafe or ambiguous listener accepted: %s", address)
		}
	}
	for _, address := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if err := validateListenAddress(address); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("OBS_AUTH_TOKEN", testAuthToken)
	if _, err := LoadConfigFromEnv(); err == nil || strings.Contains(err.Error(), testAuthToken) {
		t.Fatal("raw environment auth token accepted or exposed")
	}
}

func TestTokenFileRejectsPermissionsOwnershipSymlinksAndOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-token")
	if err := os.WriteFile(path, []byte(testAuthToken+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// The public loader requires uid0. Test the file-validation implementation
	// against this process's uid without granting a production ownership bypass.
	owner := uint32(os.Geteuid())
	if got, err := readTokenFile(path, owner); err != nil || got != testAuthToken {
		t.Fatalf("valid token file failed: %v", err)
	}
	if _, err := readTokenFile(path, owner+1); err == nil {
		t.Fatal("wrong token owner accepted")
	}
	link := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(link, owner); err == nil {
		t.Fatal("token symlink accepted")
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(path, owner); err == nil {
		t.Fatal("group-readable auth token accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"short", testAuthToken + "\n\n", strings.Repeat("x", 512) + "\r\nextra-sensitive-token"} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readTokenFile(path, owner); err == nil || strings.Contains(err.Error(), "sensitive-token") {
			t.Fatal("invalid/oversized token accepted or exposed")
		}
	}
}
