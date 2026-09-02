package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
)

func TestOtpAuthURL_EncodesLabelAndQueryValues(t *testing.T) {
	issuer := "Example & Co:東京"
	account := "alice smith:ops&测试"
	secret := "ABC+& =?"

	got := OtpAuthURL(issuer, account, secret)
	wantPath := "/Example%20%26%20Co%3A%E6%9D%B1%E4%BA%AC:alice%20smith%3Aops%26%E6%B5%8B%E8%AF%95"
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse OtpAuthURL: %v", err)
	}
	if parsed.Scheme != "otpauth" || parsed.Host != "totp" {
		t.Fatalf("unexpected URL prefix: %s", got)
	}
	if parsed.EscapedPath() != wantPath {
		t.Errorf("escaped path = %q, want %q", parsed.EscapedPath(), wantPath)
	}
	if values := parsed.Query(); values.Get("issuer") != issuer || values.Get("secret") != secret {
		t.Errorf("query values were not preserved: %v", values)
	}
}

func TestGenerateBackupCodes_CountAndLength(t *testing.T) {
	cfg := config.Get().TOTP
	codes, jsonStr, err := GenerateBackupCodes()
	if err != nil {
		t.Fatalf("GenerateBackupCodes failed: %v", err)
	}
	if len(codes) != cfg.BackupCodesCount {
		t.Fatalf("expected %d codes, got %d", cfg.BackupCodesCount, len(codes))
	}
	for i, c := range codes {
		if len(c) != cfg.BackupCodeLength {
			t.Errorf("code %d has length %d, expected %d", i, len(c), cfg.BackupCodeLength)
		}
	}
	if jsonStr == "" {
		t.Fatal("expected non-empty JSON string")
	}
	if CountBackupCodes(jsonStr) != cfg.BackupCodesCount {
		t.Fatalf("CountBackupCodes: expected %d, got %d", cfg.BackupCodesCount, CountBackupCodes(jsonStr))
	}
}

func TestVerifyAndConsumeBackupCode_Match(t *testing.T) {
	codes, jsonStr, err := GenerateBackupCodes()
	if err != nil {
		t.Fatal(err)
	}

	// Try to verify each code
	remaining := jsonStr
	for i, code := range codes {
		matched, updated, err := VerifyAndConsumeBackupCode(code, remaining)
		if err != nil {
			t.Fatalf("code %d: VerifyAndConsume failed: %v", i, err)
		}
		if !matched {
			t.Fatalf("code %d (%s) should have matched", i, code)
		}
		remaining = updated
	}

	if CountBackupCodes(remaining) != 0 {
		t.Fatalf("expected 0 codes remaining, got %d", CountBackupCodes(remaining))
	}
}

func TestVerifyAndConsumeBackupCode_NoMatch(t *testing.T) {
	_, jsonStr, err := GenerateBackupCodes()
	if err != nil {
		t.Fatal(err)
	}

	matched, _, err := VerifyAndConsumeBackupCode("WRONGCODE", jsonStr)
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Error("should not have matched wrong code")
	}
}

func TestVerifyAndConsumeBackupCode_CaseInsensitive(t *testing.T) {
	codes, jsonStr, err := GenerateBackupCodes()
	if err != nil {
		t.Fatal(err)
	}

	// Test lowercase
	matched, _, err := VerifyAndConsumeBackupCode(strings.ToLower(codes[0]), jsonStr)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Error("lowercase code should match")
	}
}

func TestVerifyAndConsumeBackupCode_EmptyJSON(t *testing.T) {
	matched, _, err := VerifyAndConsumeBackupCode("anything", "")
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Error("should not match on empty JSON")
	}
}

func TestCountBackupCodes_Empty(t *testing.T) {
	if CountBackupCodes("") != 0 {
		t.Error("empty string should have 0 codes")
	}
	if CountBackupCodes("[]") != 0 {
		t.Error("empty JSON array should have 0 codes")
	}
}

func TestVerify(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}

	code, err := GenerateCode(secret, timeNow())
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(secret, code) {
		t.Error("valid TOTP code should verify")
	}
	if Verify(secret, "000000") {
		t.Error("random code should not verify")
	}
	for _, invalid := range []string{"12345", "1234567", "12345a", " 123456", "１２３４５６"} {
		if Verify(secret, invalid) {
			t.Errorf("malformed TOTP code %q should not verify", invalid)
		}
	}
}

// timeNow is a test helper to avoid importing time directly.
func timeNow() time.Time {
	return time.Now()
}
