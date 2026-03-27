package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
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

const (
	NumBackupCodes   = 10
	BackupCodeLength = 8
)

// GenerateBackupCodes creates NumBackupCodes random alphanumeric codes.
// Returns the plain codes (to show the user once) and a JSON string of bcrypt hashes (to store).
func GenerateBackupCodes() ([]string, string, error) {
	codes := make([]string, NumBackupCodes)
	hashes := make([]string, NumBackupCodes)
	for i := range codes {
		code, err := randomCode(BackupCodeLength)
		if err != nil {
			return nil, "", fmt.Errorf("generate backup code: %w", err)
		}
		codes[i] = code
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", fmt.Errorf("hash backup code: %w", err)
		}
		hashes[i] = string(hash)
	}
	jsonBytes, err := json.Marshal(hashes)
	if err != nil {
		return nil, "", fmt.Errorf("marshal backup codes: %w", err)
	}
	return codes, string(jsonBytes), nil
}

// VerifyAndConsumeBackupCode checks code against the stored hashed backup codes.
// If matched, removes the used code and returns the updated JSON string.
// Returns (true, updatedJSON, nil) on match, (false, originalJSON, nil) on mismatch.
func VerifyAndConsumeBackupCode(code, storedJSON string) (bool, string, error) {
	code = strings.TrimSpace(strings.ToUpper(code))
	if storedJSON == "" {
		return false, storedJSON, nil
	}
	var hashes []string
	if err := json.Unmarshal([]byte(storedJSON), &hashes); err != nil {
		return false, storedJSON, fmt.Errorf("unmarshal backup codes: %w", err)
	}
	for i, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(code)) == nil {
			// Match: remove this code
			hashes = append(hashes[:i], hashes[i+1:]...)
			updated, err := json.Marshal(hashes)
			if err != nil {
				return true, storedJSON, fmt.Errorf("marshal updated codes: %w", err)
			}
			return true, string(updated), nil
		}
	}
	return false, storedJSON, nil
}

// CountBackupCodes returns the number of remaining backup codes.
func CountBackupCodes(storedJSON string) int {
	if storedJSON == "" {
		return 0
	}
	var hashes []string
	if err := json.Unmarshal([]byte(storedJSON), &hashes); err != nil {
		return 0
	}
	return len(hashes)
}

// randomCode generates a random alphanumeric string of the given length.
func randomCode(length int) (string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O/1/I confusion
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}
