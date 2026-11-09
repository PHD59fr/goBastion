package db

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/secretstore"
	"goBastion/internal/utils/cryptokey"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openSecretImportDB(t *testing.T) *gorm.DB {
	t.Helper()
	database, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "import.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	connection.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = connection.Close() })
	if err := database.AutoMigrate(ManagedModelsInDependencyOrder()...); err != nil {
		t.Fatal(err)
	}
	return database
}

func encryptSecretImportFixture(t *testing.T, plaintext string) string {
	t.Helper()
	value, err := cryptokey.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// Keep this inventory independent of secretstore's private column list: an
// accidentally omitted family must fail the import/restore regression tests.
var secretImportColumns = []struct{ table, primary, secret string }{
	{"group_db_accesses", "id", "password"},
	{"group_egress_keys", "id", "priv_key"},
	{"group_guest_db_accesses", "id", "password"},
	{"self_db_accesses", "id", "password"},
	{"self_egress_keys", "id", "priv_key"},
	{"ssh_host_keys", "type", "private_key"},
	{"users", "id", "totp_secret"},
}

func seedSecretImportFixture(t *testing.T, database *gorm.DB) {
	t.Helper()
	group := models.Group{Name: "legacy-import-group"}
	if err := database.Create(&group).Error; err != nil {
		t.Fatal(err)
	}
	for _, deleted := range []bool{false, true} {
		user := models.User{
			Username: fmt.Sprintf("legacy-import-%t", deleted), Role: models.RoleUser,
			TOTPEnabled: true, TOTPSecret: "JBSWY3DPEHPK3PXP",
		}
		if err := database.Create(&user).Error; err != nil {
			t.Fatal(err)
		}
		rows := []any{
			&user,
			&models.SelfEgressKey{UserID: user.ID, PubKey: "self-public", PrivKey: "legacy-self-private", Type: "ed25519", Size: 256, Fingerprint: fmt.Sprintf("self-%t", deleted)},
			&models.GroupEgressKey{GroupID: group.ID, PubKey: "group-public", PrivKey: "legacy-group-private", Type: "ed25519", Size: 256, Fingerprint: fmt.Sprintf("group-%t", deleted)},
			&models.SelfDBAccess{UserID: user.ID, Host: "self.example", Port: 5432, Protocol: "postgres", Username: "reader", Password: "legacy-self-password"},
			&models.GroupDBAccess{GroupID: group.ID, Host: "group.example", Port: 3306, Protocol: "mysql", Username: "reader", Password: "legacy-group-password"},
			&models.GroupGuestDBAccess{GroupID: group.ID, UserID: user.ID, Host: "guest.example", Port: 6379, Protocol: "redis", Username: "default", Password: "legacy-guest-password"},
		}
		for i, row := range rows {
			if i != 0 {
				if err := database.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			if deleted {
				if err := database.Model(row).UpdateColumn("deleted_at", time.Now().UTC()).Error; err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	for _, hostType := range []string{"ed25519", "sftp-proxy-ed25519"} {
		// Include non-UTF8 bytes so binary host keys cannot silently be treated
		// as JSON strings during backup restoration.
		if err := database.Create(&models.SshHostKey{Type: hostType,
			PrivateKey: []byte("legacy-host-private\x00\xff"), PublicKey: []byte("host-public")}).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func snapshotSecretImport(t *testing.T, database *gorm.DB) map[string]string {
	t.Helper()
	values := make(map[string]string)
	for _, column := range secretImportColumns {
		var rows []struct {
			ID    string
			Value []byte
		}
		if err := database.Table(column.table).
			Select(column.primary + " AS id, " + column.secret + " AS value").Find(&rows).Error; err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			values[column.table+"/"+row.ID] = string(row.Value)
		}
	}
	return values
}

func exportSecretImportFixture(t *testing.T, source *gorm.DB) []byte {
	t.Helper()
	t.Setenv("DB_EXPORT_KEY", "0123456789abcdef0123456789abcdef")
	var backup bytes.Buffer
	if err := Export(source, &backup, nil); err != nil {
		t.Fatal(err)
	}
	return backup.Bytes()
}

func assertSecretImportEmpty(t *testing.T, database *gorm.DB) {
	t.Helper()
	for _, model := range ManagedModelsInDependencyOrder() {
		var count int64
		if err := database.Unscoped().Model(model).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("failed import left %d rows in %T", count, model)
		}
	}
}

func TestImportRejectsPlaintextSecretsAndRollsBack(t *testing.T) {
	source := openSecretImportDB(t)
	seedSecretImportFixture(t, source)
	backup := exportSecretImportFixture(t, source)
	target := openSecretImportDB(t)
	if err := Import(target, bytes.NewReader(backup), nil); err == nil {
		t.Fatal("normal import accepted plaintext persistent secrets")
	}
	assertSecretImportEmpty(t, target)
}

func TestSecretMigrationImportUpgradesEverySecretIncludingDeletedRows(t *testing.T) {
	source := openSecretImportDB(t)
	seedSecretImportFixture(t, source)
	want := snapshotSecretImport(t, source)
	if len(want) != 14 {
		t.Fatalf("fixture covers %d values, want 14", len(want))
	}
	backup := exportSecretImportFixture(t, source)
	target := openSecretImportDB(t)
	if err := ImportForSecretMigration(target, bytes.NewReader(backup), nil); err != nil {
		t.Fatal(err)
	}
	keyID, err := cryptokey.ActiveKeyID()
	if err != nil {
		t.Fatal(err)
	}
	stored := snapshotSecretImport(t, target)
	if len(stored) != len(want) {
		t.Fatalf("restore changed secret row count: got %d want %d", len(stored), len(want))
	}
	for name, plaintext := range want {
		if !strings.HasPrefix(stored[name], "gob:v2:"+keyID+":") {
			t.Fatalf("%s was not upgraded to the active envelope", name)
		}
		decrypted, err := cryptokey.Decrypt(stored[name])
		if err != nil || decrypted != plaintext {
			t.Fatalf("%s did not preserve its secret bytes", name)
		}
	}
	if err := secretstore.ValidateStored(target); err != nil {
		t.Fatal(err)
	}
	// A restored DB must also support the ordinary encrypted export/import path.
	regularTarget := openSecretImportDB(t)
	if err := Import(regularTarget, bytes.NewReader(exportSecretImportFixture(t, target)), nil); err != nil {
		t.Fatal(err)
	}
	if got := snapshotSecretImport(t, regularTarget); len(got) != len(stored) {
		t.Fatal("normal encrypted import lost secret rows")
	} else {
		for name, ciphertext := range stored {
			if got[name] != ciphertext {
				t.Fatalf("normal encrypted import modified %s", name)
			}
		}
	}
}

func TestSecretMigrationImportRejectsUnreadableSecretsAndRollsBack(t *testing.T) {
	activeID, err := cryptokey.ActiveKeyID()
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := make([]byte, 32)
	if _, err := rand.Read(wrongKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	header := "gob:v2:" + activeID + ":"
	wrongKeyCiphertext := header + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte("TOTP"), []byte(header)))
	for _, tc := range []struct{ name, value string }{
		{"corrupt", "gob:v2:" + activeID + ":invalid"},
		{"wrong-key", wrongKeyCiphertext},
		{"missing-key-id", "gob:v2:unavailable-key:invalid"},
		{"unsupported-version", "gob:v99:invalid"},
		{"ambiguous-legacy", base64.StdEncoding.EncodeToString(make([]byte, 40))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := openSecretImportDB(t)
			seedSecretImportFixture(t, source)
			// Users are last in the migration inventory, so this also exercises
			// rollback after earlier imported passwords and keys were rewritten.
			if err := source.Unscoped().Model(&models.User{}).
				Where("username = ?", "legacy-import-false").UpdateColumn("totp_secret", tc.value).Error; err != nil {
				t.Fatal(err)
			}
			target := openSecretImportDB(t)
			if err := ImportForSecretMigration(target, bytes.NewReader(exportSecretImportFixture(t, source)), nil); err == nil {
				t.Fatal("offline restore accepted unreadable ciphertext")
			}
			assertSecretImportEmpty(t, target)
		})
	}
}

func TestSecretMigrationImportRejectsWrongExportKeyAndRollsBack(t *testing.T) {
	source := openSecretImportDB(t)
	seedSecretImportFixture(t, source)
	backup := exportSecretImportFixture(t, source)
	t.Setenv("DB_EXPORT_KEY", "fedcba9876543210fedcba9876543210")
	target := openSecretImportDB(t)
	if err := ImportForSecretMigration(target, bytes.NewReader(backup), nil); err == nil {
		t.Fatal("offline restore accepted the wrong backup encryption key")
	}
	assertSecretImportEmpty(t, target)
}
