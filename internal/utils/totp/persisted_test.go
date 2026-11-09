package totp

import (
	"goBastion/internal/utils/cryptokey"
	"testing"
	"time"
)

func TestVerifyStoredSecretRequiresAuthenticatedCiphertext(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	code, err := GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cryptokey.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyStoredSecret(ciphertext, code) {
		t.Fatal("valid persisted TOTP failed")
	}
	for _, stored := range []string{secret, "", "gob:v1:invalid", ciphertext + "tampered"} {
		if VerifyStoredSecret(stored, code) {
			t.Fatal("unauthenticated stored TOTP accepted")
		}
	}
	if !Verify(secret, code) {
		t.Fatal("raw enrollment verification changed")
	}
}
