package autocomplete

import (
	"testing"

	appconfig "goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/c-bata/go-prompt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestCompletionHidesGroupListAllWhenPolicyBlocksIt(t *testing.T) {
	cfg := appconfig.DefaultConfig()
	cfg.Security.GroupVisibility.Mode = "members"
	appconfig.SetForTesting(cfg)
	defer appconfig.ResetForTesting()

	db := newAutocompleteTestDB(t)
	user := &models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	buf := prompt.NewBuffer()
	buf.InsertText("groupList --a", false, true)
	suggestions := Completion(*buf.Document(), user, db)
	for _, s := range suggestions {
		if s.Text == "--all" {
			t.Fatal("unexpected --all suggestion when group visibility blocks global listing")
		}
	}
}

func TestCompletionShowsGroupListAllWhenPolicyAllowsIt(t *testing.T) {
	cfg := appconfig.DefaultConfig()
	cfg.Security.GroupVisibility.Mode = "open"
	appconfig.SetForTesting(cfg)
	defer appconfig.ResetForTesting()

	db := newAutocompleteTestDB(t)
	user := &models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	buf := prompt.NewBuffer()
	buf.InsertText("groupList --a", false, true)
	suggestions := Completion(*buf.Document(), user, db)
	found := false
	for _, s := range suggestions {
		if s.Text == "--all" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected --all suggestion when group visibility is open")
	}
}

func newAutocompleteTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Group{}, &models.UserGroup{}, &models.RestrictedCommandGrant{}); err != nil {
		t.Fatalf("migrate autocomplete test DB: %v", err)
	}
	return db
}
