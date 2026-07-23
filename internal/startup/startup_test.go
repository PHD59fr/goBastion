package startup

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	cmdaccount "goBastion/internal/commands/account"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

const testPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test-key"

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.IngressKey{}, &models.SelfEgressKey{},
		&models.GroupEgressKey{}, &models.SelfAccess{}, &models.GroupAccess{},
		&models.Group{}, &models.UserGroup{}, &models.Aliases{},
		&models.KnownHostsEntry{}, &models.PIVTrustAnchor{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestBootstrap_CreateDBIngressKey_Valid(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "admin", Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	if err := cmdaccount.CreateDBIngressKey(db, &user, testPubKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var key models.IngressKey
	if err := db.Where("user_id = ?", user.ID).First(&key).Error; err != nil {
		t.Fatalf("key not found in DB: %v", err)
	}
	if key.Type == "" {
		t.Fatal("expected non-empty key type")
	}
}

func TestBootstrap_CreateDBIngressKey_Empty(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "admin", Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	err := cmdaccount.CreateDBIngressKey(db, &user, "")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
}

func TestBootstrap_CreateDBIngressKey_Invalid(t *testing.T) {
	db := newTestDB(t)
	user := models.User{Username: "admin", Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	err := cmdaccount.CreateDBIngressKey(db, &user, "not-a-valid-key garbage!!!")
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
}

func TestRunDisableTOTP_PreservesPasswordMFA(t *testing.T) {
	db := newTestDB(t)
	user := models.User{
		Username:     "alice",
		Role:         models.RoleUser,
		Enabled:      true,
		TOTPSecret:   "secret",
		TOTPEnabled:  true,
		PasswordHash: "$2a$10$abcdefghijklmnopqrstuuXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
		BackupCodes:  `["hash"]`,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = r.Close()
	})

	code := runDisableTOTP(db, log, user.Username)
	_ = w.Close()
	if code != 0 {
		t.Fatalf("runDisableTOTP exit code = %d, want 0", code)
	}

	var got models.User
	if err := db.Where("username = ?", user.Username).First(&got).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if got.PasswordHash == "" {
		t.Fatal("password MFA should be preserved by --disableTOTP")
	}
	if got.TOTPEnabled || got.TOTPSecret != "" {
		t.Fatal("TOTP should be disabled and secret cleared")
	}
	if got.BackupCodes != "" {
		t.Fatal("backup codes should be cleared")
	}
}

func TestRunDisableTOTP_NoTOTPConfiguredMessage(t *testing.T) {
	db := newTestDB(t)
	user := models.User{
		Username:     "bob",
		Role:         models.RoleUser,
		Enabled:      true,
		PasswordHash: "password-still-set",
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = r.Close()
	})

	code := runDisableTOTP(db, log, user.Username)
	_ = w.Close()
	if code != 0 {
		t.Fatalf("runDisableTOTP exit code = %d, want 0", code)
	}

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if !strings.Contains(string(out), "no TOTP or backup codes configured") {
		t.Fatalf("unexpected message: %q", string(out))
	}
}

type noopAdapter struct{}

func (noopAdapter) CreateUser(string) error                       { return nil }
func (noopAdapter) DeleteUser(string) error                       { return nil }
func (noopAdapter) UpdateSudoers(*models.User) error              { return nil }
func (noopAdapter) ChownDir(models.User, string) error            { return nil }
func (noopAdapter) ExecCommand(string, ...string) (string, error) { return "", nil }
func (noopAdapter) UserHomeExists(string) bool                    { return true }

var _ osadapter.SystemAdapter = noopAdapter{}

func TestRunRegenerateSSHHostKeysFailureReturnsError(t *testing.T) {
	db := newTestDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	oldArgs := os.Args
	os.Args = []string{"goBastion", "--regenerateSSHHostKeys"}
	t.Cleanup(func() { os.Args = oldArgs })

	code := Run(db, log, noopAdapter{})
	if code == 0 {
		t.Fatal("expected non-zero exit code when host key regeneration fails")
	}
}
