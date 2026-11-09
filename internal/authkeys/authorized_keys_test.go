package authkeys

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"goBastion/internal/models"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.IngressKey{}); err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	return db
}

func testPubKey(t *testing.T, comment string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	line := string(ssh.MarshalAuthorizedKey(pub))
	if comment != "" {
		line = line[:len(line)-1] + " " + comment + "\n"
	}
	return line
}

func TestLoadDBBootstrap(t *testing.T) {
	t.Setenv("DB_DRIVER", "")
	t.Setenv("DB_DSN", "")
	if err := loadDBBootstrap(strings.NewReader("DB_DRIVER=sqlite\nDB_DSN=/tmp/x.db\nOTHER=nope\n")); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DB_DRIVER") != "sqlite" || os.Getenv("DB_DSN") != "/tmp/x.db" {
		t.Fatalf("unexpected env: driver=%q dsn=%q", os.Getenv("DB_DRIVER"), os.Getenv("DB_DSN"))
	}
}

func TestLoadDBBootstrapPreservesEnvironmentPrecedence(t *testing.T) {
	t.Setenv("DB_DRIVER", "postgres")
	t.Setenv("DB_DSN", "")
	if err := loadDBBootstrap(strings.NewReader("DB_DRIVER=sqlite\nDB_DSN=fixture-dsn\n")); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DB_DRIVER") != "postgres" || os.Getenv("DB_DSN") != "fixture-dsn" {
		t.Fatal("bootstrap file overrode an explicit environment value")
	}
	if err := LoadDBBootstrapFromConf(); err != nil {
		t.Fatal("complete environment must not require a bootstrap file:", err)
	}
}

func TestLookupIngressKeysFiltersUsersAndKeys(t *testing.T) {
	db := testDB(t)
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	enabled := models.User{ID: uuid.New(), Username: "alice", Role: models.RoleUser, Enabled: true}
	disabled := models.User{ID: uuid.New(), Username: "bob", Role: models.RoleUser, Enabled: false}
	system := models.User{ID: uuid.New(), Username: "sys", Role: models.RoleUser, Enabled: true, SystemUser: true}
	for _, u := range []*models.User{&enabled, &disabled, &system} {
		if err := db.Select("ID", "Username", "Role", "Enabled", "SystemUser").Create(u).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Model(&models.User{}).Where("username = ?", "bob").Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	for name, dst := range map[string]*models.User{"alice": &enabled, "bob": &disabled, "sys": &system} {
		*dst = models.User{}
		if err := db.Where("username = ?", name).First(dst).Error; err != nil {
			t.Fatal(err)
		}
	}
	if disabled.Enabled || disabled.SystemUser {
		t.Fatalf("bob setup wrong: enabled=%v system=%v", disabled.Enabled, disabled.SystemUser)
	}
	if !system.SystemUser || !system.Enabled {
		t.Fatalf("sys setup wrong: enabled=%v system=%v", system.Enabled, system.SystemUser)
	}
	if enabled.ID.String() == "00000000-0000-0000-0000-000000000000" || enabled.ID == disabled.ID || enabled.ID == system.ID || disabled.ID == system.ID {
		t.Fatalf("user IDs wrong: alice=%s bob=%s sys=%s", enabled.ID, disabled.ID, system.ID)
	}
	valid := testPubKey(t, "valid")
	expired := testPubKey(t, "expired")
	for _, ik := range []models.IngressKey{
		{UserID: enabled.ID, Key: valid, Type: "ssh-rsa", Size: 2048, Fingerprint: "a"},
		{UserID: enabled.ID, Key: expired, Type: "ssh-rsa", Size: 2048, Fingerprint: "b", ExpiresAt: &past},
		{UserID: enabled.ID, Key: testPubKey(t, "future"), Type: "ssh-rsa", Size: 2048, Fingerprint: "c", ExpiresAt: &future},
		{UserID: disabled.ID, Key: testPubKey(t, "disabled"), Type: "ssh-rsa", Size: 2048, Fingerprint: "d"},
		{UserID: system.ID, Key: testPubKey(t, "system"), Type: "ssh-rsa", Size: 2048, Fingerprint: "e"},
	} {
		if err := db.Create(&ik).Error; err != nil {
			t.Fatal(err)
		}
	}

	lines, err := LookupIngressKeys(context.Background(), db, "alice", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 {
		t.Fatalf("got %d keys, want 2 (valid + future): %#v", len(lines), lines)
	}

	for _, name := range []string{"bob", "sys", "missing", "../evil", "Alice", " alice", "alice ", "alice\n"} {
		lines, err := LookupIngressKeys(context.Background(), db, name, now)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(lines) != 0 {
			t.Fatalf("%s: expected no keys, got %#v", name, lines)
		}
	}
}

func TestLoadDBBootstrapRejectsMalformedWithoutPartialEnvironment(t *testing.T) {
	t.Setenv("DB_DRIVER", "")
	t.Setenv("DB_DSN", "")
	for _, content := range []string{
		"DB_DRIVER=postgres\nDB_DSN=bad\x00value\n",
		"DB_DRIVER=postgres\n" + strings.Repeat("x", 1024*1024),
	} {
		if err := loadDBBootstrap(strings.NewReader(content)); err == nil {
			t.Fatal("invalid bootstrap accepted")
		}
		if os.Getenv("DB_DRIVER") != "" || os.Getenv("DB_DSN") != "" {
			t.Fatal("failed bootstrap partially changed environment")
		}
	}
}

func TestLoadDBBootstrapAcceptsLargeUnrelatedKeyring(t *testing.T) {
	t.Setenv("DB_DRIVER", "")
	t.Setenv("DB_DSN", "")
	content := "EGRESS_ENC_KEYS=" + strings.Repeat("x", 70*1024) + "\nDB_DRIVER=sqlite\nDB_DSN=:memory:\n"
	if err := loadDBBootstrap(strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DB_DRIVER") != "sqlite" || os.Getenv("DB_DSN") != ":memory:" {
		t.Fatal("DB bootstrap values not loaded")
	}
}

func TestLookupIngressKeysRejectsDeletedAndInvalidRows(t *testing.T) {
	db := testDB(t)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	valid := testPubKey(t, "valid")
	key := models.IngressKey{UserID: user.ID, Key: valid, Type: "ssh-rsa", Size: 2048, Fingerprint: "valid"}
	if err := db.Create(&key).Error; err != nil {
		t.Fatal(err)
	}
	for _, value := range []models.IngressKey{
		{UserID: user.ID, Key: "invalid", Type: "ssh-rsa", Fingerprint: "malformed"},
		{UserID: user.ID, Key: "cert-authority " + valid, Type: "ssh-rsa", PIVAttested: true, Fingerprint: "piv-ca"},
	} {
		if err := db.Create(&value).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Delete(&key).Error; err != nil {
		t.Fatal(err)
	}
	if keys, err := LookupIngressKeys(context.Background(), db, "alice", time.Now()); err != nil || len(keys) != 0 {
		t.Fatalf("deleted or invalid key authorized: %d, %v", len(keys), err)
	}
	if err := db.Model(&user).Update("deleted_at", time.Now()).Error; err != nil {
		t.Fatal(err)
	}
	if keys, err := LookupIngressKeys(context.Background(), db, "alice", time.Now()); err != nil || len(keys) != 0 {
		t.Fatalf("deleted user authorized: %d, %v", len(keys), err)
	}
}

func TestLookupIngressKeysFailsClosedOnDatabaseAndContextErrors(t *testing.T) {
	db := testDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if keys, err := LookupIngressKeys(ctx, db, "alice", time.Now()); !errors.Is(err, context.Canceled) || len(keys) != 0 {
		t.Fatalf("cancellation not propagated: %d, %v", len(keys), err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if keys, err := LookupIngressKeys(context.Background(), db, "alice", time.Now()); err == nil || len(keys) != 0 {
		t.Fatalf("DB failure not propagated: %d, %v", len(keys), err)
	}
}

func TestWriteIngressKeys(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteIngressKeys(&buf, []string{"ssh-ed25519 AAAA test"}); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "ssh-ed25519 AAAA test\n" {
		t.Fatalf("unexpected output: %q", buf.String())
	}
}
