package config

import (
	"testing"

	appconfig "goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestApplyValueUpdatesConfig(t *testing.T) {
	appconfig.ResetForTesting()
	cfg := appconfig.DefaultConfig()
	appconfig.SetForTesting(cfg)
	defer appconfig.ResetForTesting()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(&models.BastionInstance{}); err != nil {
		t.Fatalf("migrate bastion_instances: %v", err)
	}

	boot := &appconfig.Bootstrap{InstanceID: "test-instance"}
	t.Setenv("INSTANCE_ID", "test-instance")
	appconfig.Load()
	if err := appconfig.EnsureInstance(db); err != nil {
		t.Fatalf("ensure instance: %v", err)
	}
	_ = boot

	if err := applyValue(db, "security.group_visibility.mode", "members"); err != nil {
		t.Fatalf("applyValue group visibility: %v", err)
	}
	if err := appconfig.LoadFromDB(db); err != nil {
		t.Fatalf("reload config from DB: %v", err)
	}
	if got := appconfig.Get().Security.GroupVisibility.Mode; got != "members" {
		t.Fatalf("group visibility mode = %q, want members", got)
	}

	if err := applyValue(db, "security.egress_key_visibility.mode", "private"); err != nil {
		t.Fatalf("applyValue egress key visibility: %v", err)
	}
	if err := appconfig.LoadFromDB(db); err != nil {
		t.Fatalf("reload config from DB: %v", err)
	}
	if got := appconfig.Get().Security.EgressKeyVisibility.Mode; got != "private" {
		t.Fatalf("egress key visibility mode = %q, want private", got)
	}

	if err := applyValue(db, "splash.enabled", "false"); err != nil {
		t.Fatalf("applyValue splash: %v", err)
	}
	if err := appconfig.LoadFromDB(db); err != nil {
		t.Fatalf("reload splash config from DB: %v", err)
	}
	if appconfig.Get().Splash.Enabled {
		t.Fatal("splash enabled = true, want false")
	}
}

// TestConfigDiffKeysAreCategorized guards the section -> category mapping used
// to build the config tables. A key emitted by ConfigDiff() but attached to no
// category is silently invisible, both in the interactive TUI and in the
// non-interactive fallback. The "sync" section used to be such an orphan.
func TestConfigDiffKeysAreCategorized(t *testing.T) {
	appconfig.ResetForTesting()
	t.Cleanup(appconfig.ResetForTesting)
	appconfig.SetForTesting(appconfig.DefaultConfig())

	shown := make(map[string]bool)
	emitted := make(map[string]bool)
	for _, e := range appconfig.ConfigDiff() {
		emitted[e.Section] = true
	}

	for _, c := range categories {
		for _, e := range buildDisplayEntries(c.name) {
			if !e.isSection {
				shown[e.key] = true
			}
		}
	}

	for _, e := range appconfig.ConfigDiff() {
		key := e.Section + "." + e.Key
		if !shown[key] {
			t.Errorf("key %q is not reachable from any category: add section %q to categories", key, e.Section)
		}
	}

	// Reverse direction: a section listed in categories that matches no key is
	// either a typo or a key that no longer exists.
	for _, c := range categories {
		for _, s := range c.sections {
			if s == "mosh" && !appconfig.MoshAvailable() {
				continue // mosh.enabled is only emitted when mosh-server is installed
			}
			if !emitted[s] {
				t.Errorf("category %q lists section %q but ConfigDiff() emits no key for it", c.name, s)
			}
		}
	}
}
