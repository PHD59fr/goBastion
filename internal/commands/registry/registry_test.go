package registry

import (
	"log/slog"
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

// mockAdapter satisfies osadapter.SystemAdapter with no-ops.
type mockAdapter struct{}

func (m *mockAdapter) CreateUser(string) error                      { return nil }
func (m *mockAdapter) DeleteUser(string) error                      { return nil }
func (m *mockAdapter) UpdateSudoers(*models.User) error             { return nil }
func (m *mockAdapter) ChownDir(models.User, string) error           { return nil }
func (m *mockAdapter) ExecCommand(string, ...string) (string, error) { return "", nil }
func (m *mockAdapter) UserHomeExists(string) bool                   { return false }

var _ osadapter.SystemAdapter = (*mockAdapter)(nil)

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
		&models.Realm{}, &models.RestrictedCommandGrant{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func newAdminUser(t *testing.T, db *gorm.DB, username string) *models.User {
	t.Helper()
	u := models.User{Username: username, Role: models.RoleAdmin, Enabled: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	return &u
}

func TestBuildRegistry_CountsCommands(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	adapter := &mockAdapter{}
	exitFunc := func() {}

	cmds := BuildRegistry(db, admin, logger, adapter, nil, exitFunc)
	if len(cmds) == 0 {
		t.Fatal("expected at least one command in the registry")
	}
	// The registry contains more than 30 commands across all categories.
	if len(cmds) < 30 {
		t.Fatalf("expected at least 30 commands, got %d", len(cmds))
	}
}

func TestBuildRegistry_PermissionFiltering(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	adapter := &mockAdapter{}

	cmds := BuildRegistry(db, admin, logger, adapter, nil, func() {})

	// Admin sees all commands when hasPerm always returns true.
	allSuggestions := PromptSuggest(cmds, func(string) bool { return true })
	if len(allSuggestions) != len(cmds) {
		t.Fatalf("expected %d suggestions for admin, got %d", len(cmds), len(allSuggestions))
	}

	// User with no permissions: all commands have non-empty Permission,
	// so none pass when hasPerm always returns false.
	noPermSuggestions := PromptSuggest(cmds, func(string) bool { return false })
	if len(noPermSuggestions) >= len(cmds) {
		t.Fatalf("expected fewer suggestions for unprivileged user, got %d out of %d", len(noPermSuggestions), len(cmds))
	}
	if len(noPermSuggestions) != 0 {
		t.Fatalf("expected zero suggestions for unprivileged user, got %d", len(noPermSuggestions))
	}
}

func TestPromptArgs(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	adapter := &mockAdapter{}

	cmds := BuildRegistry(db, admin, logger, adapter, nil, func() {})

	// selfAddAccess has several Args defined.
	args := PromptArgs(cmds, "selfAddAccess", func(string) bool { return true })
	if len(args) == 0 {
		t.Fatal("expected at least one arg suggestion for selfAddAccess")
	}
	// Verify one of the known flags appears.
	found := false
	for _, a := range args {
		if a.Text == "--server" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected --server in arg suggestions for selfAddAccess")
	}
}

func TestPromptArgs_UnknownCommand(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	adapter := &mockAdapter{}

	cmds := BuildRegistry(db, admin, logger, adapter, nil, func() {})

	args := PromptArgs(cmds, "nonexistentCommand", func(string) bool { return true })
	if args != nil {
		t.Fatalf("expected nil args for unknown command, got %v", args)
	}
}
