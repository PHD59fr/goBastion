package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// GenerateSecret creates a cryptographically random 20-byte secret encoded as Base32.
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

// GenerateCode computes the 6-digit TOTP code for the given secret and time (RFC 6238).
func GenerateCode(secret string, t time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// fallback: try with padding
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("invalid TOTP secret: %w", err)
		}
	}

	counter := uint64(t.Unix()) / 30
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := (uint32(h[offset]&0x7f) << 24) |
		(uint32(h[offset+1]) << 16) |
		(uint32(h[offset+2]) << 8) |
		uint32(h[offset+3])

	return fmt.Sprintf("%06d", code%1_000_000), nil
}

// Verify checks the code against the secret with ±1 time step tolerance for clock drift.
func Verify(secret, code string) bool {
	code = strings.TrimSpace(code)
	now := time.Now()
	for _, delta := range []time.Duration{0, 30 * time.Second, -30 * time.Second} {
		expected, err := GenerateCode(secret, now.Add(delta))
		if err != nil {
			return false
		}
		if expected == code {
			return true
		}
	}
	return false
}

// OtpAuthURL returns the otpauth:// URI for QR-code enrollment with standard authenticator apps.
func OtpAuthURL(issuer, username, secret string) string {
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, username, secret, issuer,
	)
}
