package self

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddDBAliasRejectsCaseInsensitiveDuplicateInSelfScope(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	alias := models.DatabaseAlias{ResolveFrom: "ProdDB", Host: "db1", Port: 5432, Protocol: "postgres", UserID: &user.ID}
	if err := db.Create(&alias).Error; err != nil {
		t.Fatalf("seed db alias: %v", err)
	}

	if err := AddDBAlias(db, user, []string{"--alias", "proddb", "--host", "db2", "--port", "5432", "--protocol", "postgres"}); err == nil {
		t.Fatal("expected duplicate db alias error")
	}

	var count int64
	if err := db.Model(&models.DatabaseAlias{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count db aliases: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected duplicate db alias to be rejected, got %d aliases", count)
	}
}
