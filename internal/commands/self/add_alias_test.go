package self

import (
	"testing"

	"goBastion/internal/models"
)

func TestAddAliasRejectsCaseInsensitiveDuplicateInSelfScope(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	alias := models.Aliases{ResolveFrom: "Prod", Host: "srv1", UserID: &user.ID}
	if err := db.Create(&alias).Error; err != nil {
		t.Fatalf("seed alias: %v", err)
	}

	if err := AddAlias(db, user, []string{"--alias", "prod", "--hostname", "srv2"}); err == nil {
		t.Fatal("expected duplicate alias error")
	}

	var count int64
	if err := db.Model(&models.Aliases{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count aliases: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected duplicate alias to be rejected, got %d aliases", count)
	}
}
