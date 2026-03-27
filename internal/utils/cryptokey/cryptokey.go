package cryptokey

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const (
	envKey     = "EGRESS_ENC_KEY"
	dbConfFile = "/run/gobastion/db.conf"
)

var (
	gcm     cipher.AEAD
	gcmOnce sync.Once
)

// Enabled reports whether egress key encryption is configured.
func Enabled() bool {
	initGCM()
	return gcm != nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// Returns base64(nonce || ciphertext).
func Encrypt(plaintext string) (string, error) {
	if !Enabled() {
		return "", fmt.Errorf("egress key encryption not configured (set %s)", envKey)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt decrypts a base64(nonce || ciphertext) string produced by Encrypt.
// Returns the plaintext or an error.
func Decrypt(encoded string) (string, error) {
	if !Enabled() {
		return "", fmt.Errorf("egress key encryption not configured (set %s)", envKey)
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:ns], data[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return string(pt), nil
}

// DecryptOrPassThrough returns the plaintext for both encrypted and legacy plaintext values.
// If EGRESS_ENC_KEY is not set, returns raw as-is.
// If set, attempts decryption; on failure assumes legacy plaintext and returns raw.
func DecryptOrPassThrough(raw string) string {
	if !Enabled() {
		return raw
	}
	plain, err := Decrypt(raw)
	if err != nil {
		// Legacy plaintext value (stored before encryption was enabled).
		return raw
	}
	return plain
}

// ReEncryptIfNeeded takes a plaintext value and encrypts it if EGRESS_ENC_KEY is set.
// If encryption is not enabled, returns the value unchanged.
func ReEncryptIfNeeded(plaintext string) (string, error) {
	if !Enabled() {
		return plaintext, nil
	}
	// If already encrypted, don't double-encrypt.
	if IsEncrypted(plaintext) {
		return plaintext, nil
	}
	return Encrypt(plaintext)
}

// IsEncrypted returns true if the value looks like a valid encrypted blob.
// A valid encrypted blob is base64-encoded and at least (nonce + tag) bytes after decoding.
func IsEncrypted(raw string) bool {
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return false
	}
	// AES-256-GCM nonce is 12 bytes, tag is 16 bytes = minimum 28 bytes.
	return len(data) >= 28
}

// readKeyFromEnv reads EGRESS_ENC_KEY from env or fallback config file.
func readKeyFromEnv() string {
	raw := os.Getenv(envKey)
	if raw != "" {
		return raw
	}
	f, err := os.Open(dbConfFile)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if k, v, ok := strings.Cut(line, "="); ok && k == envKey {
			return v
		}
	}
	return ""
}

// initGCM lazily reads the key from environment or config file.
func initGCM() {
	gcmOnce.Do(func() {
		raw := readKeyFromEnv()
		if raw == "" {
			return
		}
		key, err := decodeKey(raw)
		if err != nil {
			return
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return
		}
		gcm = aead
	})
}

// decodeKey accepts a base64-encoded key (16/24/32 bytes) or a 32-byte raw passphrase.
func decodeKey(raw string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		switch len(decoded) {
		case 16, 24, 32:
			return decoded, nil
		}
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("key must be base64-encoded 16/24/32-byte key or 32-byte passphrase (got %d bytes)", len(raw))
}
