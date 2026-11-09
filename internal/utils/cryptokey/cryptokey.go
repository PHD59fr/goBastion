// Package cryptokey protects secrets at rest. Configuration errors are fatal to
// every nonempty secret operation; plaintext storage is never a fallback.
package cryptokey

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"goBastion/internal/config"
)

const (
	envKey          = "EGRESS_ENC_KEY"
	envKeyID        = "EGRESS_ENC_KEY_ID"
	envKeys         = "EGRESS_ENC_KEYS"
	encryptedPrefix = "gob:v2:"
	legacyPrefix    = "gob:v1:"
	maxConfigBytes  = 1 << 20
)

type keySet struct {
	activeID string
	active   cipher.AEAD
	keys     map[string]cipher.AEAD
}

var (
	gcmOnce sync.Once
	loaded  *keySet
	loadErr error
)

// Validate checks the mandatory encryption configuration. It never includes
// secret material or file contents in its errors. Configuration is immutable
// for the lifetime of a process; restart after changing keys.
func Validate() error {
	gcmOnce.Do(func() { loaded, loadErr = loadKeys() })
	return loadErr
}

// Enabled reports whether the mandatory encryption configuration is valid.
func Enabled() bool { return Validate() == nil }

// ActiveKeyID returns the identifier used for newly encrypted values.
func ActiveKeyID() (string, error) {
	if err := Validate(); err != nil {
		return "", err
	}
	return loaded.activeID, nil
}

// Encrypt writes gob:v2:<key-id>:base64(nonce || ciphertext). The full header
// is authenticated as AAD, binding both the version and key identifier.
func Encrypt(plaintext string) (string, error) {
	if err := Validate(); err != nil {
		return "", err
	}
	nonce := make([]byte, loaded.active.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", errors.New("generate encryption nonce failed")
	}
	header := encryptedPrefix + loaded.activeID + ":"
	ciphertext := loaded.active.Seal(nonce, nonce, []byte(plaintext), []byte(header))
	return header + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt authenticates v2 ciphertext, or legacy v1/unprefixed ciphertext.
// Legacy values are tried against the active and historical keys. Plaintext,
// malformed envelopes, and unavailable historical keys always return errors.
func Decrypt(encoded string) (string, error) {
	if err := Validate(); err != nil {
		return "", err
	}
	if strings.HasPrefix(encoded, encryptedPrefix) {
		id, payload, ok := strings.Cut(strings.TrimPrefix(encoded, encryptedPrefix), ":")
		if !ok || !validID(id) {
			return "", errors.New("invalid encrypted secret envelope")
		}
		aead, ok := loaded.keys[id]
		if !ok {
			return "", errors.New("encrypted secret key ID is unavailable")
		}
		return open(aead, payload, []byte(encryptedPrefix+id+":"))
	}
	if strings.HasPrefix(encoded, "gob:") && !strings.HasPrefix(encoded, legacyPrefix) {
		return "", errors.New("unsupported encrypted secret version")
	}
	payload := strings.TrimPrefix(encoded, legacyPrefix)
	if plaintext, err := open(loaded.active, payload, nil); err == nil {
		return plaintext, nil
	}
	for id, aead := range loaded.keys {
		if id == loaded.activeID {
			continue
		}
		if plaintext, err := open(aead, payload, nil); err == nil {
			return plaintext, nil
		}
	}
	return "", errors.New("secret ciphertext authentication failed")
}

func open(aead cipher.AEAD, payload string, aad []byte) (string, error) {
	data, err := base64.StdEncoding.Strict().DecodeString(payload)
	if err != nil || base64.StdEncoding.EncodeToString(data) != payload || len(data) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("invalid encrypted secret payload")
	}
	plaintext, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], aad)
	if err != nil {
		return "", errors.New("secret ciphertext authentication failed")
	}
	return string(plaintext), nil
}

// DecryptOrPassThrough retains its historical name for callers. Only an
// explicitly empty optional secret passes through; nonempty plaintext fails.
func DecryptOrPassThrough(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	return Decrypt(raw)
}

// ReEncryptIfNeeded encrypts plaintext or rotates authenticated ciphertext to
// the active v2 key. Marked but invalid ciphertext is rejected.
func ReEncryptIfNeeded(value string) (string, error) {
	if err := Validate(); err != nil {
		return "", err
	}
	plaintext, err := Decrypt(value)
	if err == nil {
		if !NeedsRotation(value) {
			return value, nil
		}
		return Encrypt(plaintext)
	}
	if strings.HasPrefix(value, "gob:") {
		return "", err
	}
	return Encrypt(value)
}

// IsEncrypted authenticates a value instead of merely checking its prefix.
func IsEncrypted(raw string) bool {
	_, err := Decrypt(raw)
	return err == nil
}

// NeedsRotation returns false only for authenticated v2 ciphertext using the
// active key. Call Decrypt first when an error must be distinguished from an
// older ciphertext that can be rotated.
func NeedsRotation(raw string) bool {
	if err := Validate(); err != nil {
		return true
	}
	if !strings.HasPrefix(raw, encryptedPrefix+loaded.activeID+":") {
		return true
	}
	return !IsEncrypted(raw)
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", c) {
			return false
		}
	}
	return true
}

func loadKeys() (*keySet, error) {
	values, err := readSettings()
	if err != nil {
		return nil, err
	}
	raw, err := resolveSecret(values, envKey)
	if err != nil {
		return nil, err
	}
	key, err := decodeKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must contain a canonical base64 AES-256 key", envKey)
	}
	id := "default"
	if value, ok := values[envKeyID]; ok {
		id = value
	}
	if !validID(id) {
		return nil, errors.New("EGRESS_ENC_KEY_ID must contain 1-64 letters, digits, dots, underscores or hyphens")
	}
	active, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	result := &keySet{activeID: id, active: active, keys: map[string]cipher.AEAD{id: active}}
	historical, err := resolveSecret(values, envKeys)
	if err != nil {
		return nil, err
	}
	if historical == "" {
		return result, nil
	}
	keyring, err := parseKeyring(historical)
	if err != nil {
		return nil, err
	}
	for previousID, previousRaw := range keyring {
		if !validID(previousID) {
			return nil, errors.New("EGRESS_ENC_KEYS contains an invalid key ID")
		}
		previous, err := decodeHistoricalKey(previousRaw)
		if err != nil {
			return nil, errors.New("EGRESS_ENC_KEYS contains an invalid AES key")
		}
		if previousID == id {
			if !bytes.Equal(previous, key) {
				return nil, errors.New("EGRESS_ENC_KEYS conflicts with the active key ID")
			}
			continue
		}
		aead, err := newAEAD(previous)
		if err != nil {
			return nil, err
		}
		result.keys[previousID] = aead
	}
	return result, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("initialize encryption cipher failed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize authenticated encryption failed")
	}
	return aead, nil
}

func decodeKey(raw string) ([]byte, error) {
	decoded, err := decodeHistoricalKey(raw)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("key must be canonical base64 encoding of exactly 32 bytes")
	}
	return decoded, nil
}

// Historical keys are decryption-only. Previous releases accepted AES-128 and
// AES-192, so these keys must remain usable for authenticated offline upgrades.
// Newly encrypted values always use the strictly AES-256 active key.
func decodeHistoricalKey(raw string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(raw)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != raw {
		return nil, errors.New("historical key must be canonical base64 encoding of an AES key")
	}
	switch len(decoded) {
	case 16, 24, 32:
		return decoded, nil
	default:
		return nil, errors.New("historical key must encode 16, 24 or 32 bytes")
	}
}

// parseKeyring rejects duplicate JSON members; encoding/json's ordinary map
// decoder would silently accept the last value, hiding configuration mistakes.
func parseKeyring(raw string) (map[string]string, error) {
	invalid := errors.New("EGRESS_ENC_KEYS must be a JSON object of unique key IDs to base64 keys")
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, invalid
	}
	keys := make(map[string]string)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, invalid
		}
		id, ok := token.(string)
		if !ok {
			return nil, invalid
		}
		if _, exists := keys[id]; exists {
			return nil, invalid
		}
		var value string
		if err := decoder.Decode(&value); err != nil {
			return nil, invalid
		}
		keys[id] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid
	}
	return keys, nil
}

func resolveSecret(values map[string]string, name string) (string, error) {
	direct, hasDirect := values[name]
	file, hasFile := values[name+"_FILE"]
	if hasDirect && hasFile {
		return "", fmt.Errorf("%s and %s_FILE cannot both be configured", name, name)
	}
	if !hasFile {
		return direct, nil
	}
	if file == "" {
		return "", fmt.Errorf("%s_FILE must identify a readable secret file", name)
	}
	f, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("cannot read %s_FILE", name)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil || len(data) > maxConfigBytes {
		return "", fmt.Errorf("cannot read %s_FILE", name)
	}
	// Docker/Kubernetes secret files commonly include a single final newline.
	return strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r"), nil
}

func readSettings() (map[string]string, error) {
	return readSettingsFrom(config.Get().Paths.DbConfFile)
}

func readSettingsFrom(path string) (map[string]string, error) {
	names := []string{envKey, envKey + "_FILE", envKeyID, envKeys, envKeys + "_FILE"}
	// An explicitly supplied active key makes the environment the complete
	// encryption configuration. ForceCommand children may inherit these settings
	// while being unable to read root's bootstrap directory. Do not consult it,
	// or inherit stale key IDs/keyrings from a different configuration source.
	_, hasActiveKey := os.LookupEnv(envKey)
	_, hasActiveFile := os.LookupEnv(envKey + "_FILE")
	if hasActiveKey || hasActiveFile {
		values := make(map[string]string)
		for _, name := range names {
			if value, ok := os.LookupEnv(name); ok {
				values[name] = value
			}
		}
		return values, nil
	}
	known := make(map[string]bool)
	for _, name := range names {
		known[name] = true
	}
	values := make(map[string]string)
	f, err := os.Open(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("cannot read encryption bootstrap configuration")
	}
	if err == nil {
		defer func() { _ = f.Close() }()
		scanner := bufio.NewScanner(io.LimitReader(f, maxConfigBytes+1))
		scanner.Buffer(make([]byte, 4096), maxConfigBytes)
		total := 0
		for scanner.Scan() {
			line := scanner.Text()
			total += len(line) + 1
			if total > maxConfigBytes {
				return nil, errors.New("encryption bootstrap configuration is too large")
			}
			name, value, ok := strings.Cut(line, "=")
			if !ok || !known[name] {
				continue
			}
			if _, exists := values[name]; exists {
				return nil, errors.New("duplicate encryption bootstrap setting")
			}
			values[name] = value
		}
		if scanner.Err() != nil {
			return nil, errors.New("cannot read encryption bootstrap configuration")
		}
	}
	// Environment overrides each secret family atomically, so an environment
	// key does not accidentally combine with a stale bootstrap _FILE setting.
	for _, name := range []string{envKey, envKeys} {
		direct, hasDirect := os.LookupEnv(name)
		file, hasFile := os.LookupEnv(name + "_FILE")
		if hasDirect || hasFile {
			delete(values, name)
			delete(values, name+"_FILE")
			if hasDirect {
				values[name] = direct
			}
			if hasFile {
				values[name+"_FILE"] = file
			}
		}
	}
	if id, ok := os.LookupEnv(envKeyID); ok {
		values[envKeyID] = id
	}
	return values, nil
}
