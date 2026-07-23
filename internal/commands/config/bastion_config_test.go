package config

import (
	"testing"

	appconfig "goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestApplyValueUpdatesNestedVisibilityConfig(t *testing.T) {
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
}
