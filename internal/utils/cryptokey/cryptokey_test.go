package cryptokey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"goBastion/internal/config"
)

const testKey = "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo="

var otherKey = base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))

func resetGCM() {
	gcmOnce = sync.Once{}
	loaded = nil
	loadErr = nil
}

func setup(t *testing.T) {
	t.Helper()
	resetGCM()
	for _, name := range []string{envKey, envKey + "_FILE", envKeyID, envKeys, envKeys + "_FILE"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Get()
	old := cfg.Paths.DbConfFile
	cfg.Paths.DbConfFile = filepath.Join(t.TempDir(), "db.conf")
	t.Cleanup(func() { cfg.Paths.DbConfFile = old; resetGCM() })
}

func setKey(t *testing.T) { t.Helper(); t.Setenv(envKey, testKey) }

func TestMandatoryKey(t *testing.T) {
	setup(t)
	if err := Validate(); err == nil {
		t.Fatal("missing key accepted")
	}
	if Enabled() {
		t.Fatal("missing key enabled encryption")
	}
	for _, op := range []func() (string, error){
		func() (string, error) { return Encrypt("secret") },
		func() (string, error) { return Decrypt("secret") },
		func() (string, error) { return ReEncryptIfNeeded("secret") },
		func() (string, error) { return DecryptOrPassThrough("secret") },
	} {
		if got, err := op(); err == nil || got != "" {
			t.Fatal("missing key did not fail closed")
		}
	}
	if got, err := DecryptOrPassThrough(""); got != "" || err != nil {
		t.Fatal("explicit empty optional secret failed")
	}
}

func TestCanonicalAES256Only(t *testing.T) {
	for _, raw := range []string{"", "01234567890123456789012345678901", "invalid-sensitive-key", base64.StdEncoding.EncodeToString(make([]byte, 16)), base64.StdEncoding.EncodeToString(make([]byte, 24)), testKey + "\n", " " + testKey, strings.TrimSuffix(testKey, "=")} {
		t.Run(raw, func(t *testing.T) {
			setup(t)
			t.Setenv(envKey, raw)
			if err := Validate(); err == nil {
				t.Fatal("invalid key accepted")
			} else if raw != "" && strings.Contains(err.Error(), raw) {
				t.Fatal("error exposed key")
			}
		})
	}
}

func TestRoundTripAndPlaintextRejection(t *testing.T) {
	setup(t)
	setKey(t)
	plain := "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----"
	first, err := Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Encrypt(plain)
	if err != nil || first == second {
		t.Fatal("encryption did not randomize nonce")
	}
	if !strings.HasPrefix(first, "gob:v2:default:") || !IsEncrypted(first) || NeedsRotation(first) {
		t.Fatal("incorrect v2 classification")
	}
	if got, err := DecryptOrPassThrough(first); err != nil || got != plain {
		t.Fatalf("roundtrip failed: %v", err)
	}
	if _, err := DecryptOrPassThrough(plain); err == nil {
		t.Fatal("plaintext accepted")
	}
	if _, err := DecryptOrPassThrough("QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="); err == nil {
		t.Fatal("base64 plaintext accepted")
	}
	if got, err := ReEncryptIfNeeded(first); err != nil || got != first {
		t.Fatal("current ciphertext unnecessarily changed")
	}
	if got, err := ReEncryptIfNeeded(plain); err != nil || !IsEncrypted(got) {
		t.Fatal("plaintext was not encrypted")
	}
	if id, err := ActiveKeyID(); err != nil || id != "default" {
		t.Fatal("incorrect active key ID")
	}
}

func TestTamperWrongKeyAndUnknownVersion(t *testing.T) {
	setup(t)
	setKey(t)
	original, err := Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envKeys, `{"alias":"`+testKey+`"}`)
	resetGCM()
	// Even an available alias pointing at the same key cannot substitute for
	// the authenticated key ID in the envelope.
	for _, raw := range []string{
		strings.Replace(original, ":default:", ":alias:", 1),
		strings.Replace(original, ":default:", ":missing:", 1),
		original[:len(original)-4] + "AAAA",
		original + "\n",
		"gob:v2:default:invalid", "gob:v3:default:invalid", "gob:v1:invalid",
	} {
		if _, err := Decrypt(raw); err == nil {
			t.Fatal("tampered/invalid ciphertext accepted")
		}
		if _, err := ReEncryptIfNeeded(raw); err == nil {
			t.Fatal("marked invalid ciphertext treated as plaintext")
		}
		if IsEncrypted(raw) {
			t.Fatal("invalid ciphertext classified as encrypted")
		}
	}
	t.Setenv(envKey, otherKey)
	t.Setenv(envKeys, "{}")
	resetGCM()
	if _, err := Decrypt(original); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestRotationAndLegacyAuthentication(t *testing.T) {
	setup(t)
	setKey(t)
	t.Setenv(envKeyID, "old")
	old, err := Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	// Construct the previous release's AES-GCM payload with nil AAD.
	nonce := make([]byte, loaded.active.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	legacy := base64.StdEncoding.EncodeToString(loaded.active.Seal(nonce, nonce, []byte("secret"), nil))
	t.Setenv(envKey, otherKey)
	t.Setenv(envKeyID, "new")
	t.Setenv(envKeys, `{"old":"`+testKey+`"}`)
	resetGCM()
	for _, raw := range []string{old, legacy, legacyPrefix + legacy} {
		if got, err := Decrypt(raw); err != nil || got != "secret" {
			t.Fatalf("historical decryption failed: %v", err)
		}
		if !NeedsRotation(raw) {
			t.Fatal("historical value not marked for rotation")
		}
		rotated, err := ReEncryptIfNeeded(raw)
		if err != nil || !strings.HasPrefix(rotated, "gob:v2:new:") || NeedsRotation(rotated) {
			t.Fatalf("rotation failed: %v", err)
		}
		if got, err := Decrypt(rotated); err != nil || got != "secret" {
			t.Fatal("rotation changed plaintext")
		}
	}
	t.Setenv(envKeys, "{}")
	resetGCM()
	for _, raw := range []string{old, legacy, legacyPrefix + legacy} {
		if _, err := DecryptOrPassThrough(raw); err == nil {
			t.Fatal("removed historical key accepted")
		}
	}
}

func TestKeyringValidation(t *testing.T) {
	for _, ring := range []string{`null`, `[]`, `{"old":1}`, `{"old":"` + testKey + `","old":"` + otherKey + `"}`, `{"bad:id":"` + testKey + `"}`, `{"old":"secret-invalid"}`, `{"default":"` + otherKey + `"}`, `{} {}`} {
		t.Run(ring, func(t *testing.T) {
			setup(t)
			setKey(t)
			t.Setenv(envKeys, ring)
			if err := Validate(); err == nil {
				t.Fatal("invalid keyring accepted")
			} else if strings.Contains(err.Error(), testKey) || strings.Contains(err.Error(), "secret-invalid") {
				t.Fatal("error exposed key material")
			}
		})
	}
	for _, id := range []string{"", "bad:id", "bad\nid", strings.Repeat("x", 65)} {
		t.Run("id", func(t *testing.T) {
			setup(t)
			setKey(t)
			t.Setenv(envKeyID, id)
			if Validate() == nil {
				t.Fatal("invalid active ID accepted")
			}
		})
	}
}

func writeSecret(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSecretFiles(t *testing.T) {
	setup(t)
	keyPath := writeSecret(t, "key", testKey+"\n")
	ringPath := writeSecret(t, "ring", `{"old":"`+otherKey+`"}`+"\n")
	t.Setenv(envKey+"_FILE", keyPath)
	t.Setenv(envKeys+"_FILE", ringPath)
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	if !Enabled() {
		t.Fatal("file configuration invalid")
	}
	t.Setenv(envKey, testKey)
	resetGCM()
	if Validate() == nil {
		t.Fatal("direct and file conflict accepted")
	}
	if err := os.Unsetenv(envKey); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envKeys, "{}")
	resetGCM()
	if Validate() == nil {
		t.Fatal("keyring direct and file conflict accepted")
	}
	if err := os.Unsetenv(envKeys); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envKey+"_FILE", filepath.Join(t.TempDir(), "sensitive-path"))
	resetGCM()
	if err := Validate(); err == nil || strings.Contains(err.Error(), "sensitive-path") {
		t.Fatal("file error missing or exposes file path")
	}
}

func TestBootstrapFallbackAndEnvironmentPrecedence(t *testing.T) {
	setup(t)
	cfg := config.Get()
	content := envKey + "=" + testKey + "\n" + envKeyID + "=bootstrap\n" + envKeys + "={\"old\":\"" + otherKey + "\"}\n"
	if err := os.WriteFile(cfg.Paths.DbConfFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	if id, _ := ActiveKeyID(); id != "bootstrap" {
		t.Fatal("bootstrap ID not loaded")
	}
	// A complete environment family supersedes stale bootstrap file references.
	if err := os.WriteFile(cfg.Paths.DbConfFile, []byte(envKey+"_FILE=/missing\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setKey(t)
	t.Setenv(envKeyID, "environment")
	resetGCM()
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	if id, _ := ActiveKeyID(); id != "environment" {
		t.Fatal("environment ID not loaded")
	}
	if err := os.WriteFile(cfg.Paths.DbConfFile, []byte(envKey+"="+testKey+"\n"+envKey+"="+testKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv(envKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv(envKeyID); err != nil {
		t.Fatal(err)
	}
	resetGCM()
	if Validate() == nil {
		t.Fatal("duplicate bootstrap key accepted")
	}
}

func TestEnvironmentOwnsConfigurationWithoutBootstrapAccess(t *testing.T) {
	setup(t)
	directory := t.TempDir()
	path := filepath.Join(directory, "db.conf")
	if err := os.WriteFile(path, []byte(envKey+"="+otherKey+"\n"+envKeyID+"=stale\n"+envKeys+"=invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0700) })
	config.Get().Paths.DbConfFile = path
	setKey(t)
	t.Setenv(envKeyID, "environment")
	t.Setenv(envKeys, `{"old":"`+otherKey+`"}`)
	if err := Validate(); err != nil {
		t.Fatalf("environment-owned config read inaccessible bootstrap: %v", err)
	}
	if id, _ := ActiveKeyID(); id != "environment" {
		t.Fatal("active ID inherited from bootstrap")
	}
	if _, ok := loaded.keys["old"]; !ok {
		t.Fatal("environment historical key not loaded")
	}
	// Omitting optional environment settings must use defaults, never stale
	// bootstrap settings. A directory also causes a read error even under root.
	if err := os.Unsetenv(envKeyID); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv(envKeys); err != nil {
		t.Fatal(err)
	}
	config.Get().Paths.DbConfFile = directory
	resetGCM()
	if err := Validate(); err != nil {
		t.Fatalf("environment key consulted bootstrap: %v", err)
	}
	if id, _ := ActiveKeyID(); id != "default" {
		t.Fatal("absent environment ID did not use default")
	}
	if len(loaded.keys) != 1 {
		t.Fatal("absent environment keyring inherited bootstrap")
	}
	// An explicitly empty active key must fail instead of reading a fallback.
	t.Setenv(envKey, "")
	resetGCM()
	if Validate() == nil {
		t.Fatal("empty explicit environment key fell back")
	}
}

func TestHistoricalAES128And192AreDecryptionOnly(t *testing.T) {
	for _, size := range []int{16, 24} {
		t.Run(fmt.Sprintf("AES-%d", size*8), func(t *testing.T) {
			setup(t)
			setKey(t)
			historicalKey := []byte(strings.Repeat("k", size))
			historicalBase64 := base64.StdEncoding.EncodeToString(historicalKey)
			t.Setenv(envKeys, `{"legacy":"`+historicalBase64+`"}`)
			if err := Validate(); err != nil {
				t.Fatal(err)
			}
			oldAEAD, err := newAEAD(historicalKey)
			if err != nil {
				t.Fatal(err)
			}
			nonce := make([]byte, oldAEAD.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			legacy := base64.StdEncoding.EncodeToString(oldAEAD.Seal(nonce, nonce, []byte("legacy-secret"), nil))
			for _, raw := range []string{legacy, legacyPrefix + legacy} {
				plaintext, err := Decrypt(raw)
				if err != nil || plaintext != "legacy-secret" {
					t.Fatalf("historical AES-%d read failed: %v", size*8, err)
				}
				rotated, err := ReEncryptIfNeeded(raw)
				if err != nil || !strings.HasPrefix(rotated, "gob:v2:default:") || NeedsRotation(rotated) {
					t.Fatalf("historical AES-%d rotation failed: %v", size*8, err)
				}
				// Independently authenticate the new envelope with the 256-bit active
				// key: the short historical key must never be selected for new writes.
				activeKey, err := decodeKey(testKey)
				if err != nil {
					t.Fatal(err)
				}
				activeAEAD, err := newAEAD(activeKey)
				if err != nil {
					t.Fatal(err)
				}
				payload := strings.TrimPrefix(rotated, "gob:v2:default:")
				plaintext, err = open(activeAEAD, payload, []byte("gob:v2:default:"))
				if err != nil || plaintext != "legacy-secret" {
					t.Fatal("rotation did not use AES-256 active key")
				}
				if _, err := open(oldAEAD, payload, []byte("gob:v2:default:")); err == nil {
					t.Fatal("writer reused short historical key")
				}
			}
			t.Setenv(envKeys, "{}")
			resetGCM()
			if _, err := Decrypt(legacyPrefix + legacy); err == nil {
				t.Fatal("retired historical short key still accepted")
			}
		})
	}
}
