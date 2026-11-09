package secretstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"goBastion/internal/utils/cryptokey"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const migrationTestKey = "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo="

var rotationTestKey = base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))

func TestMain(m *testing.M) {
	if os.Getenv("GOB_SECRETSTORE_HELPER_MODE") == "" {
		_ = os.Setenv("EGRESS_ENC_KEY", migrationTestKey)
		_ = os.Setenv("EGRESS_ENC_KEY_ID", "active")
		for _, name := range []string{"EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE"} {
			_ = os.Unsetenv(name)
		}
	}
	os.Exit(m.Run())
}

type fixtureColumn struct {
	table, primary, secret string
	binary                 bool
}

// This fixed inventory is independent of the implementation's column slice so
// omitted persistent-secret families and wrong primary keys fail these tests.
var fixtureColumns = []fixtureColumn{
	{"group_db_accesses", "id", "password", false},
	{"group_egress_keys", "id", "priv_key", false},
	{"group_guest_db_accesses", "id", "password", false},
	{"self_db_accesses", "id", "password", false},
	{"self_egress_keys", "id", "priv_key", false},
	{"ssh_host_keys", "type", "private_key", true},
	{"users", "id", "totp_secret", false},
}

func migrationDB(t *testing.T, path string, create bool) *gorm.DB {
	t.Helper()
	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	connection.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = connection.Close() })
	if create {
		for _, c := range fixtureColumns {
			valueType := "TEXT"
			if c.binary {
				valueType = "BLOB"
			}
			query := fmt.Sprintf("CREATE TABLE %s (%s TEXT PRIMARY KEY, %s %s, deleted_at TEXT)", c.table, c.primary, c.secret, valueType)
			if err := database.Exec(query).Error; err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"active", "deleted"} {
				plain := fixturePlaintext(c.table, id)
				var value any = plain
				if c.binary {
					value = []byte(plain)
				}
				var deleted any
				if id == "deleted" {
					deleted = "2025-01-01 00:00:00"
				}
				query = fmt.Sprintf("INSERT INTO %s (%s,%s,deleted_at) VALUES (?,?,?)", c.table, c.primary, c.secret)
				if err := database.Exec(query, id, value, deleted).Error; err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return database
}

func fixturePlaintext(table, id string) string { return "plaintext-secret/" + table + "/" + id }

func snapshotSecrets(t *testing.T, database *gorm.DB) map[string]string {
	t.Helper()
	snapshot := make(map[string]string)
	for _, c := range fixtureColumns {
		var rows []struct {
			ID    string
			Value []byte
		}
		query := fmt.Sprintf("SELECT %s AS id,%s AS value FROM %s ORDER BY %s", c.primary, c.secret, c.table, c.primary)
		if err := database.Raw(query).Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			snapshot[c.table+"/"+row.ID] = string(row.Value)
		}
	}
	return snapshot
}

func setFixtureSecret(t *testing.T, database *gorm.DB, table, id, value string) {
	t.Helper()
	for _, c := range fixtureColumns {
		if c.table != table {
			continue
		}
		var stored any = value
		if c.binary {
			stored = []byte(value)
		}
		if err := database.Table(table).Where(c.primary+" = ?", id).UpdateColumn(c.secret, stored).Error; err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("unknown fixture table")
}

func assertSnapshot(t *testing.T, database *gorm.DB, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(snapshotSecrets(t, database), want) {
		t.Fatal("migration changed rows outside a successful apply")
	}
}

func TestMigrationExplicitPlaintextDryRunApplyAndIdempotence(t *testing.T) {
	database := migrationDB(t, ":memory:", true)
	original := snapshotSecrets(t, database)
	if len(original) != 14 {
		t.Fatal("fixture must cover active and soft-deleted rows in all seven tables")
	}
	for _, options := range []Options{{}, {Apply: true}} {
		result, err := Migrate(database, options)
		if err == nil || result.Changed != 0 || result.Applied {
			t.Fatal("plaintext was accepted without explicit authorization")
		}
		assertSnapshot(t, database, original)
	}
	if err := ValidateStored(database); err == nil {
		t.Fatal("startup validation accepted plaintext")
	}
	result, err := Migrate(database, Options{AllowPlaintext: true})
	if err != nil || result.Version != MigrationVersion || result.Checked != 14 || result.Changed != 14 || result.Applied {
		t.Fatalf("incorrect dry-run result: %+v, %v", result, err)
	}
	assertSnapshot(t, database, original)
	result, err = Migrate(database, Options{Apply: true, AllowPlaintext: true})
	if err != nil || result.Checked != 14 || result.Changed != 14 || !result.Applied {
		t.Fatalf("apply failed: %+v, %v", result, err)
	}
	encrypted := snapshotSecrets(t, database)
	for name, raw := range encrypted {
		if raw == original[name] || !strings.HasPrefix(raw, "gob:v2:active:") {
			t.Fatalf("row %s was not encrypted", name)
		}
		plaintext, err := cryptokey.Decrypt(raw)
		if err != nil || plaintext != original[name] {
			t.Fatalf("row %s changed plaintext: %v", name, err)
		}
	}
	// The host-key column must remain binary, including its soft-deleted row.
	var blobCount int64
	if err := database.Raw("SELECT count(*) FROM ssh_host_keys WHERE typeof(private_key) = 'blob'").Scan(&blobCount).Error; err != nil || blobCount != 2 {
		t.Fatal("host-key ciphertext did not preserve BLOB storage")
	}
	if err := ValidateStored(database); err != nil {
		t.Fatalf("encrypted startup validation failed: %v", err)
	}
	result, err = Migrate(database, Options{Apply: true})
	if err != nil || result.Checked != 14 || result.Changed != 0 || !result.Applied {
		t.Fatalf("idempotent apply failed: %+v, %v", result, err)
	}
	assertSnapshot(t, database, encrypted)
}

func encryptFixture(t *testing.T, keyText, id, plaintext string, legacy bool) string {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(keyText)
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
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	header := "gob:v2:" + id + ":"
	aad := []byte(header)
	if legacy {
		header = ""
		aad = nil
	}
	return header + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, []byte(plaintext), aad))
}

func TestLegacyAuthenticatedCiphertextMigratesWithoutPlaintextPermission(t *testing.T) {
	database := migrationDB(t, ":memory:", true)
	original := snapshotSecrets(t, database)
	for i, c := range fixtureColumns {
		for _, id := range []string{"active", "deleted"} {
			legacy := encryptFixture(t, migrationTestKey, "", original[c.table+"/"+id], true)
			if i%2 == 0 {
				legacy = "gob:v1:" + legacy
			}
			setFixtureSecret(t, database, c.table, id, legacy)
		}
	}
	before := snapshotSecrets(t, database)
	result, err := Migrate(database, Options{})
	if err != nil || result.Changed != 14 || result.Applied {
		t.Fatalf("legacy dry run failed: %+v, %v", result, err)
	}
	assertSnapshot(t, database, before)
	result, err = Migrate(database, Options{Apply: true})
	if err != nil || result.Changed != 14 {
		t.Fatalf("legacy apply failed: %+v, %v", result, err)
	}
	for name, raw := range snapshotSecrets(t, database) {
		plaintext, err := cryptokey.Decrypt(raw)
		if err != nil || plaintext != original[name] || cryptokey.NeedsRotation(raw) {
			t.Fatalf("legacy migration failed for %s", name)
		}
	}
}

func TestMigrationRejectsUnreadableRowsAndRollsBackEveryTable(t *testing.T) {
	cases := map[string]string{
		"corrupt marked":     "gob:v2:active:corrupt-sensitive-secret",
		"unknown version":    "gob:v9:active:unsupported-sensitive-secret",
		"wrong key":          encryptFixture(t, rotationTestKey, "active", "wrong-key-secret", false),
		"unavailable key":    encryptFixture(t, rotationTestKey, "retired", "historical-secret", false),
		"wrong unmarked key": encryptFixture(t, rotationTestKey, "", "wrong-legacy-secret", true),
		"ambiguous base64":   base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 40)),
	}
	for name, invalid := range cases {
		t.Run(name, func(t *testing.T) {
			database := migrationDB(t, ":memory:", true)
			// users is the last migration table: every other table has already been
			// rewritten when this row fails authentication, proving whole-tx rollback.
			setFixtureSecret(t, database, "users", "deleted", invalid)
			before := snapshotSecrets(t, database)
			result, err := Migrate(database, Options{Apply: true, AllowPlaintext: true})
			if err == nil || result.Changed != 0 || result.Applied {
				t.Fatalf("unsafe row accepted: %+v, %v", result, err)
			}
			if strings.Contains(err.Error(), invalid) || strings.Contains(err.Error(), "sensitive-secret") {
				t.Fatal("migration diagnostic exposed secret")
			}
			assertSnapshot(t, database, before)
		})
	}
}

func TestMigrationWriteFailureRollsBackEarlierTables(t *testing.T) {
	database := migrationDB(t, ":memory:", true)
	before := snapshotSecrets(t, database)
	if err := database.Exec("CREATE TRIGGER refuse_secret_update BEFORE UPDATE ON users BEGIN SELECT RAISE(ABORT, 'injected write failure'); END").Error; err != nil {
		t.Fatal(err)
	}
	result, err := Migrate(database, Options{Apply: true, AllowPlaintext: true})
	if err == nil || result.Changed != 0 || result.Applied {
		t.Fatal("write failure did not abort migration")
	}
	assertSnapshot(t, database, before)
}

func TestEmptyOptionalSecretsArePreservedAndRequiredSecretsFail(t *testing.T) {
	for _, table := range []string{"group_egress_keys", "self_egress_keys", "ssh_host_keys"} {
		t.Run(table, func(t *testing.T) {
			database := migrationDB(t, ":memory:", true)
			setFixtureSecret(t, database, table, "deleted", "")
			before := snapshotSecrets(t, database)
			if result, err := Migrate(database, Options{Apply: true, AllowPlaintext: true}); err == nil || result.Changed != 0 {
				t.Fatal("empty required secret accepted")
			}
			assertSnapshot(t, database, before)
		})
	}
	database := migrationDB(t, ":memory:", true)
	for _, table := range []string{"group_db_accesses", "group_guest_db_accesses", "self_db_accesses", "users"} {
		setFixtureSecret(t, database, table, "deleted", "")
	}
	result, err := Migrate(database, Options{Apply: true, AllowPlaintext: true})
	if err != nil || result.Checked != 10 || result.Changed != 10 {
		t.Fatalf("optional empty secret migration failed: %+v, %v", result, err)
	}
	after := snapshotSecrets(t, database)
	for _, table := range []string{"group_db_accesses", "group_guest_db_accesses", "self_db_accesses", "users"} {
		if after[table+"/deleted"] != "" {
			t.Fatal("optional empty secret changed")
		}
	}
	if err := ValidateStored(database); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationRotationAcrossFreshProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rotation.db")
	database := migrationDB(t, path, true)
	original := snapshotSecrets(t, database)
	runRotationProcess(t, path, "seed", migrationTestKey, "old", "")
	old := snapshotSecrets(t, database)
	for name, raw := range old {
		if raw == original[name] || !strings.HasPrefix(raw, "gob:v2:old:") {
			t.Fatalf("old-key seed failed for %s", name)
		}
	}
	runRotationProcess(t, path, "rotate", rotationTestKey, "next", `{"old":"`+migrationTestKey+`"}`)
	rotated := snapshotSecrets(t, database)
	for name, raw := range rotated {
		if raw == old[name] || !strings.HasPrefix(raw, "gob:v2:next:") {
			t.Fatalf("rotation failed for %s", name)
		}
	}
	// Retiring the historical key must leave all seven families readable and
	// idempotent in a process which has never loaded the previous key.
	runRotationProcess(t, path, "verify", rotationTestKey, "next", "")
	assertSnapshot(t, database, rotated)
}

func runRotationProcess(t *testing.T, path, mode, key, id, ring string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestMigrationRotationProcess$")
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "EGRESS_ENC_") || strings.HasPrefix(name, "GOB_SECRETSTORE_HELPER_") {
			continue
		}
		command.Env = append(command.Env, entry)
	}
	command.Env = append(command.Env, "GOB_SECRETSTORE_HELPER_MODE="+mode, "GOB_SECRETSTORE_HELPER_PATH="+path, "EGRESS_ENC_KEY="+key, "EGRESS_ENC_KEY_ID="+id)
	if ring != "" {
		command.Env = append(command.Env, "EGRESS_ENC_KEYS="+ring)
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("rotation %s child failed: %v\n%s", mode, err, output)
	}
}

func TestMigrationRotationProcess(t *testing.T) {
	mode := os.Getenv("GOB_SECRETSTORE_HELPER_MODE")
	if mode == "" {
		t.Skip("rotation subprocess helper")
	}
	database := migrationDB(t, os.Getenv("GOB_SECRETSTORE_HELPER_PATH"), false)
	options := Options{Apply: true, AllowPlaintext: mode == "seed"}
	result, err := Migrate(database, options)
	wantChanges := 14
	if mode == "verify" {
		wantChanges = 0
	}
	if err != nil || result.Checked != 14 || result.Changed != wantChanges || !result.Applied {
		t.Fatalf("rotation helper failed: %+v, %v", result, err)
	}
	for _, c := range fixtureColumns {
		for _, id := range []string{"active", "deleted"} {
			raw := snapshotSecrets(t, database)[c.table+"/"+id]
			plaintext, err := cryptokey.Decrypt(raw)
			if err != nil || plaintext != fixturePlaintext(c.table, id) || cryptokey.NeedsRotation(raw) {
				t.Fatalf("rotated row %s/%s failed authentication", c.table, id)
			}
		}
	}
	if err := ValidateStored(database); err != nil {
		t.Fatal(err)
	}
}
