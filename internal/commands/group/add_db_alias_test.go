package group

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddDBAliasRejectsCaseInsensitiveDuplicateInGroupScope(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	group := models.Group{Name: "infra"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	alias := models.DatabaseAlias{ResolveFrom: "ProdDB", Host: "db1", Port: 5432, Protocol: "postgres", GroupID: &group.ID}
	if err := db.Create(&alias).Error; err != nil {
		t.Fatalf("seed db alias: %v", err)
	}

	if err := AddDBAlias(db, admin, []string{"--group", "infra", "--alias", "proddb", "--host", "db2", "--port", "5432", "--protocol", "postgres"}); err == nil {
		t.Fatal("expected duplicate group db alias error")
	}

	var count int64
	if err := db.Model(&models.DatabaseAlias{}).Where("group_id = ?", group.ID).Count(&count).Error; err != nil {
		t.Fatalf("count db aliases: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected duplicate db alias to be rejected, got %d aliases", count)
	}
}
