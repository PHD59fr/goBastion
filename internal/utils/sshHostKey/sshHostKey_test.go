package sshHostKey

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"goBastion/internal/config"
	"goBastion/internal/models"
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
		PrivateKey: []byte("system-private"),
		PublicKey:  []byte("system-public"),
	}).Error; err != nil {
		t.Fatalf("insert system ssh host key: %v", err)
	}
	if err := db.Create(&models.SshHostKey{
		Type:       sftpProxyHostKeyType,
		PrivateKey: []byte("private"),
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
