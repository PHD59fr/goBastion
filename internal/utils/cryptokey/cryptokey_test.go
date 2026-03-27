package cryptokey

import (
	"sync"
	"testing"
)

// testKey is a base64-encoded AES-256 key (32 bytes).
const testKey = "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo="

// resetGCM clears the lazy init state so a new key can be loaded.
func resetGCM() {
	gcmOnce = sync.Once{}
	gcm = nil
}

func TestReEncryptIfNeeded_NoKey(t *testing.T) {
	resetGCM()
	t.Setenv(envKey, "")

	got, err := ReEncryptIfNeeded("plaintext-key-here")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "plaintext-key-here" {
		t.Fatalf("expected plaintext passthrough, got %q", got)
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	resetGCM()
	t.Setenv(envKey, testKey)

	if !Enabled() {
		t.Fatal("encryption should be enabled after setting env var")
	}

	plaintext := "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----"
	encrypted, err := Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if encrypted == plaintext {
		t.Fatal("encrypted should differ from plaintext")
	}

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if decrypted != plaintext {
		t.Fatalf("roundtrip mismatch: got %q", decrypted)
	}
}

func TestIsEncrypted(t *testing.T) {
	if IsEncrypted("-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Error("ssh key should not look encrypted")
	}
	if IsEncrypted("") {
		t.Error("empty string should not look encrypted")
	}
}

func TestDecryptOrPassThrough_Legacy(t *testing.T) {
	resetGCM()
	t.Setenv(envKey, testKey)

	// Legacy plaintext value should pass through.
	plain := "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----"
	got := DecryptOrPassThrough(plain)
	if got != plain {
		t.Fatalf("legacy plaintext should pass through, got %q", got)
	}
}

func TestReEncryptIfNeeded_WithKey(t *testing.T) {
	resetGCM()
	t.Setenv(envKey, testKey)

	// Plaintext should be encrypted when key is set.
	got, err := ReEncryptIfNeeded("plaintext-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "plaintext-key" {
		t.Fatal("expected encryption, got plaintext")
	}
	if !IsEncrypted(got) {
		t.Fatal("result should look encrypted")
	}

	// Already encrypted value should not be double-encrypted.
	got2, err := ReEncryptIfNeeded(got)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got2 != got {
		t.Fatal("already encrypted value should not be re-encrypted")
	}
}
