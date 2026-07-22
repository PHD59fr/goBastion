package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddAliasRejectsCaseInsensitiveDuplicateInGroupScope(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	group := models.Group{Name: "infra"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	alias := models.Aliases{ResolveFrom: "Prod", Host: "srv1", GroupID: &group.ID}
	if err := db.Create(&alias).Error; err != nil {
		t.Fatalf("seed alias: %v", err)
	}

	if err := AddAlias(db, admin, []string{"--group", "infra", "--alias", "prod", "--hostname", "srv2"}); err != nil {
		t.Fatalf("AddAlias returned error: %v", err)
	}

	var count int64
	if err := db.Model(&models.Aliases{}).Where("group_id = ?", group.ID).Count(&count).Error; err != nil {
		t.Fatalf("count aliases: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected duplicate alias to be rejected, got %d aliases", count)
	}
}
