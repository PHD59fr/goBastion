package self

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateEgressKey_ValidationErrors(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	tests := []struct {
		name string
		args []string
	}{
		{name: "empty type", args: []string{"--type", ""}},
		{name: "unsupported type", args: []string{"--type", "dsa"}},
		{name: "weak RSA key", args: []string{"--type", "rsa", "--size", "1024"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := GenerateEgressKey(db, user, test.args); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestPasswordCommands_NoConfiguredPasswordIsError(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := ChangePassword(db, user, slog.Default(), nil); err == nil {
		t.Fatal("expected change-password error")
	}
	if err := DisablePassword(db, user, slog.Default(), nil); err == nil {
		t.Fatal("expected disable-password error")
	}
}

func TestAddIngressKeyPIV_NoTrustAnchorsIsError(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	attestPath, intermediatePath := writePIVTestFiles(t)

	err := AddIngressKeyPIV(db, user, []string{
		"--attest", attestPath,
		"--intermediate", intermediatePath,
		"ssh-ed25519", "unused",
	})
	if err == nil || !strings.Contains(err.Error(), "no PIV trust anchors") {
		t.Fatalf("expected no-anchor error, got %v", err)
	}
}

func TestAddIngressKeyPIV_TrustAnchorQueryError(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	attestPath, intermediatePath := writePIVTestFiles(t)
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get SQL DB: %v", err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatalf("close SQL DB: %v", err)
	}

	err = AddIngressKeyPIV(db, user, []string{
		"--attest", attestPath,
		"--intermediate", intermediatePath,
		"ssh-ed25519", "unused",
	})
	if err == nil || !strings.Contains(err.Error(), "failed to load PIV trust anchors") {
		t.Fatalf("expected trust-anchor query error, got %v", err)
	}
}

func writePIVTestFiles(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	attestPath := filepath.Join(dir, "attest.pem")
	intermediatePath := filepath.Join(dir, "intermediate.pem")
	if err := os.WriteFile(attestPath, []byte("attestation"), 0600); err != nil {
		t.Fatalf("write attestation file: %v", err)
	}
	if err := os.WriteFile(intermediatePath, []byte("intermediate"), 0600); err != nil {
		t.Fatalf("write intermediate file: %v", err)
	}
	return attestPath, intermediatePath
}
