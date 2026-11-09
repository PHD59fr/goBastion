package sshHostKey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/cryptokey"
)

func newHostKeyTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(&models.SshHostKey{}); err != nil {
		t.Fatalf("migrate ssh_host_keys: %v", err)
	}
	return db
}

func TestEnsureSFTPProxyHostKey_PersistsStableKey(t *testing.T) {
	db := newHostKeyTestDB(t)

	_, publicKey1, fingerprint1, err := EnsureSFTPProxyHostKey(db, false)
	if err != nil {
		t.Fatalf("first EnsureSFTPProxyHostKey: %v", err)
	}
	_, publicKey2, fingerprint2, err := EnsureSFTPProxyHostKey(db, false)
	if err != nil {
		t.Fatalf("second EnsureSFTPProxyHostKey: %v", err)
	}

	if publicKey1 == "" || fingerprint1 == "" {
		t.Fatal("expected non-empty SFTP proxy host key material")
	}
	if publicKey1 != publicKey2 {
		t.Fatal("expected persisted SFTP proxy public key to remain stable")
	}
	if fingerprint1 != fingerprint2 {
		t.Fatal("expected persisted SFTP proxy fingerprint to remain stable")
	}
}

func TestEnsureSFTPProxyHostKey_ForceRegeneratesKey(t *testing.T) {
	db := newHostKeyTestDB(t)

	_, publicKey1, fingerprint1, err := EnsureSFTPProxyHostKey(db, false)
	if err != nil {
		t.Fatalf("initial EnsureSFTPProxyHostKey: %v", err)
	}
	_, publicKey2, fingerprint2, err := EnsureSFTPProxyHostKey(db, true)
	if err != nil {
		t.Fatalf("forced EnsureSFTPProxyHostKey: %v", err)
	}

	if publicKey1 == publicKey2 {
		t.Fatal("expected forced regeneration to replace public key")
	}
	if fingerprint1 == fingerprint2 {
		t.Fatal("expected forced regeneration to replace fingerprint")
	}
}

func TestRestoreSSHHostKeys_IgnoresSFTPProxyHostKey(t *testing.T) {
	db := newHostKeyTestDB(t)
	if err := db.Create(&models.SshHostKey{
		Type:       "ed25519",
		PrivateKey: encryptedHostFixture(t, "system-private"),
		PublicKey:  []byte("system-public"),
	}).Error; err != nil {
		t.Fatalf("insert system ssh host key: %v", err)
	}
	if err := db.Create(&models.SshHostKey{
		Type:       sftpProxyHostKeyType,
		PrivateKey: encryptedHostFixture(t, "private"),
		PublicKey:  []byte("public"),
	}).Error; err != nil {
		t.Fatalf("insert sftp proxy host key: %v", err)
	}

	config.ResetForTesting()
	t.Cleanup(config.ResetForTesting)
	cfg := config.Load()
	cfg.Paths.SshHostKeyDir = t.TempDir()

	if err := RestoreSSHHostKeys(db); err != nil {
		t.Fatalf("RestoreSSHHostKeys: %v", err)
	}

	sftpPath := filepath.Join(cfg.Paths.SshHostKeyDir, "ssh_host_"+sftpProxyHostKeyType+"_key")
	if _, err := os.Stat(sftpPath); !os.IsNotExist(err) {
		t.Fatalf("expected no sshd host key file for SFTP proxy key, got err=%v", err)
	}
}

func TestMain(m *testing.M) {
	_ = os.Setenv("EGRESS_ENC_KEY", "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo=")
	_ = os.Unsetenv("EGRESS_ENC_KEY_FILE")
	_ = os.Unsetenv("EGRESS_ENC_KEYS")
	_ = os.Unsetenv("EGRESS_ENC_KEYS_FILE")
	_ = os.Setenv("EGRESS_ENC_KEY_ID", "test")
	os.Exit(m.Run())
}
func encryptedHostFixture(t *testing.T, raw string) []byte {
	t.Helper()
	value, err := cryptokey.Encrypt(raw)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(value)
}
func TestHostKeyStorageIsEncrypted(t *testing.T) {
	db := newHostKeyTestDB(t)
	if _, _, _, err := EnsureSFTPProxyHostKey(db, false); err != nil {
		t.Fatal(err)
	}
	var key models.SshHostKey
	if err := db.First(&key).Error; err != nil {
		t.Fatal(err)
	}
	if !cryptokey.IsEncrypted(string(key.PrivateKey)) {
		t.Fatal("private key was stored without encryption")
	}
}
func TestRestoreRejectsPlaintextAndTraversal(t *testing.T) {
	for _, kind := range []string{"ed25519", "../../outside"} {
		t.Run(kind, func(t *testing.T) {
			db := newHostKeyTestDB(t)
			if err := db.Create(&models.SshHostKey{Type: kind, PrivateKey: []byte("PLAINTEXT"), PublicKey: []byte("public")}).Error; err != nil {
				t.Fatal(err)
			}
			config.ResetForTesting()
			t.Cleanup(config.ResetForTesting)
			cfg := config.Load()
			cfg.Paths.SshHostKeyDir = t.TempDir()
			if err := RestoreSSHHostKeys(db); err == nil {
				t.Fatal("unsafe host key accepted")
			}
			entries, err := os.ReadDir(cfg.Paths.SshHostKeyDir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("unsafe key wrote a file: %v", err)
			}
		})
	}
}
func TestAtomicHostKeyWriteDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := writeHostKeyFile(path, []byte("new-key"), 0600); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "unchanged" {
		t.Fatal("followed symlink")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe file permissions")
	}
}
