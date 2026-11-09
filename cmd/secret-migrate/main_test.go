package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goBastion/internal/config"
	bastiondb "goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/secretstore"
	"goBastion/internal/utils/cryptokey"

	"gorm.io/gorm"
)

const backupTestKey = "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo="
const backupSecretMarker = "unencrypted-legacy-totp-secret/backup-fixture"

func backupDatabase(t *testing.T) (*gorm.DB, string) {
	t.Helper()
	config.ResetForTesting()
	t.Cleanup(config.ResetForTesting)
	t.Setenv("DB_DRIVER", "sqlite")
	path := filepath.Join(t.TempDir(), "bastion.db")
	t.Setenv("DB_DSN", path)
	t.Setenv("EGRESS_ENC_KEY", backupTestKey)
	t.Setenv("EGRESS_ENC_KEY_ID", "test")
	for _, name := range []string{"EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	database, err := bastiondb.Init(backupLogger(), true)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	user := models.User{Username: "backup-fixture", Enabled: true, TOTPEnabled: true, TOTPSecret: backupSecretMarker}
	if err := database.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	return database, path
}

func backupLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestWriteBackupRequiresExportKeyAndRemovesIncompleteFile(t *testing.T) {
	database, _ := backupDatabase(t)
	t.Setenv("DB_EXPORT_KEY", "")
	path := filepath.Join(t.TempDir(), "backup.json")
	if err := writeBackup(database, path, backupLogger()); err == nil {
		t.Fatal("backup succeeded without encryption key")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("failed export left an incomplete backup")
	}
	var user models.User
	if err := database.Where("username = ?", "backup-fixture").First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if user.TOTPSecret != backupSecretMarker {
		t.Fatal("backup failure changed database secret")
	}
}

func TestWriteBackupRefusesExistingPathsAndSymlinks(t *testing.T) {
	database, _ := backupDatabase(t)
	t.Setenv("DB_EXPORT_KEY", backupTestKey)
	directory := t.TempDir()
	existing := filepath.Join(directory, "existing.json")
	original := []byte("existing backup must never be truncated")
	if err := os.WriteFile(existing, original, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(existing, symlink); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{existing, symlink, directory} {
		if err := writeBackup(database, path, backupLogger()); err == nil {
			t.Fatal("existing backup path accepted")
		}
		got, err := os.ReadFile(existing)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("existing file was changed")
		}
	}
	if info, err := os.Lstat(symlink); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("refused symlink was removed or replaced")
	}
}

func TestWriteBackupEncryptsLegacySecretsAndUsesPrivatePermissions(t *testing.T) {
	database, _ := backupDatabase(t)
	t.Setenv("DB_EXPORT_KEY", backupTestKey)
	path := filepath.Join(t.TempDir(), "encrypted-backup.json")
	if err := writeBackup(database, path, backupLogger()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("backup file is not mode 0600")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(backupSecretMarker)) {
		t.Fatal("backup exposed plaintext secret")
	}
	var envelope struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
		Nonce   string `json:"nonce"`
		Payload string `json:"payload"`
		KDF     struct {
			Name string `json:"name"`
		} `json:"kdf"`
	}
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Format != "gobastion-dbexport" || envelope.Version != 1 || envelope.KDF.Name != "direct" {
		t.Fatal("backup did not use encrypted logical export format")
	}
	key, err := base64.StdEncoding.DecodeString(backupTestKey)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		t.Fatalf("backup authentication failed: %v", err)
	}
	if !bytes.Contains(plaintext, []byte(backupSecretMarker)) {
		t.Fatal("encrypted backup omitted pre-migration secret")
	}
	var decoded struct {
		Tables []struct {
			Name string `json:"name"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(plaintext, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Tables) != len(bastiondb.ManagedModelsInDependencyOrder()) {
		t.Fatal("backup omitted managed tables")
	}
}

func TestCLIValidatesFlagsBeforeOpeningDatabase(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		diagnostic string
	}{
		{"unknown flag", []string{"--unknown"}, "flag provided but not defined"},
		{"invalid boolean", []string{"--apply=invalid"}, "invalid boolean value"},
		{"positional argument", []string{"unexpected"}, ""},
		{"apply needs backup", []string{"--apply"}, "--apply requires --backup"},
		{"plaintext apply needs backup", []string{"--apply", "--allow-plaintext"}, "--apply requires --backup"},
		{"restore cannot allow plaintext", []string{"--restore-backup", "backup.json", "--allow-plaintext"}, "--restore-backup cannot be combined"},
		{"restore cannot request backup", []string{"--restore-backup", "backup.json", "--backup", "new.json"}, "--restore-backup cannot be combined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			if code := run(tc.args, &out, &diagnostics); code != 2 {
				t.Fatalf("invalid flags returned %d", code)
			}
			if out.Len() != 0 || !strings.Contains(diagnostics.String(), tc.diagnostic) {
				t.Fatalf("unexpected flag diagnostics: %s", diagnostics.String())
			}
		})
	}
}

func TestCLIRequiresAdministrativeContextForDryRunAndApply(t *testing.T) {
	// Real authorization is exercised without injecting or overriding uid checks.
	t.Setenv("SSH_CONNECTION", "192.0.2.1 1234 192.0.2.2 22")
	for _, args := range [][]string{nil, {"--allow-plaintext"}, {"--apply", "--backup", filepath.Join(t.TempDir(), "backup.json")}} {
		var out, diagnostics bytes.Buffer
		if code := run(args, &out, &diagnostics); code != 2 || !strings.Contains(diagnostics.String(), "root administrative console") || out.Len() != 0 {
			t.Fatal("SSH context reached migration")
		}
	}
}

func TestCLIActualDryRunAndApply(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("successful administrative CLI runs require actual root; no authorization bypass")
	}
	for _, name := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		t.Setenv(name, "")
	}
	database, _ := backupDatabase(t)
	checkSecret := func(wantEncrypted bool) {
		t.Helper()
		var user models.User
		if err := database.Where("username = ?", "backup-fixture").First(&user).Error; err != nil {
			t.Fatal(err)
		}
		if !wantEncrypted {
			if user.TOTPSecret != backupSecretMarker {
				t.Fatal("dry run/failure changed stored secret")
			}
		} else {
			plain, err := cryptokey.Decrypt(user.TOTPSecret)
			if err != nil || plain != backupSecretMarker {
				t.Fatal("apply failed to encrypt secret")
			}
		}
	}
	invoke := func(args []string, wantExit int) secretstore.Result {
		t.Helper()
		var out, diagnostics bytes.Buffer
		if code := run(args, &out, &diagnostics); code != wantExit {
			t.Fatalf("CLI exited %d, expected %d: %s", code, wantExit, diagnostics.String())
		}
		var result secretstore.Result
		if wantExit == 0 {
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	invoke(nil, 1)
	checkSecret(false)
	dryRun := invoke([]string{"--allow-plaintext"}, 0)
	if dryRun.Applied || dryRun.Changed != 1 {
		t.Fatal("default command was not a dry run")
	}
	checkSecret(false)
	backup := filepath.Join(t.TempDir(), "backup.json")
	t.Setenv("DB_EXPORT_KEY", "")
	invoke([]string{"--apply", "--allow-plaintext", "--backup", backup}, 1)
	checkSecret(false)
	if _, err := os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("failed apply left backup")
	}
	t.Setenv("DB_EXPORT_KEY", backupTestKey)
	applied := invoke([]string{"--apply", "--allow-plaintext", "--backup", backup}, 0)
	if !applied.Applied || applied.Changed != 1 {
		t.Fatal("apply did not report migration")
	}
	checkSecret(true)
	if info, err := os.Stat(backup); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("apply did not produce private backup")
	}
}
