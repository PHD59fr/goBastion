package self

import (
	"testing"

	"goBastion/internal/models"

	"github.com/google/uuid"
)

func TestDelAccess_Success(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	access := models.SelfAccess{
		UserID:   user.ID,
		Server:   "1.2.3.4",
		Username: "root",
		Port:     22,
		Protocol: "ssh",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create access: %v", err)
	}

	err := DelAccess(db, user, []string{"--id", access.ID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	if err := db.Model(&models.SelfAccess{}).Where("id = ?", access.ID).Count(&count).Error; err != nil {
		t.Fatalf("count access: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected access to be hidden by soft delete, count=%d", count)
	}

	var deleted models.SelfAccess
	if err := db.Unscoped().Where("id = ?", access.ID).First(&deleted).Error; err != nil {
		t.Fatalf("find soft-deleted access: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Fatal("expected access deleted_at to be set")
	}
}

func TestDelAccess_MissingAndNotFoundAreErrors(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := DelAccess(db, user, nil); err == nil {
		t.Fatal("expected missing ID error")
	}
	if err := DelAccess(db, user, []string{"--id", uuid.NewString()}); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestDelDBAccess_Success(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	access := models.SelfDBAccess{
		UserID:   user.ID,
		Host:     "db.example.com",
		Port:     5432,
		Protocol: "postgres",
		Username: "alice",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create DB access: %v", err)
	}

	if err := DelDBAccess(db, user, []string{"--id", access.ID.String()}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	if err := db.Model(&models.SelfDBAccess{}).Where("id = ?", access.ID).Count(&count).Error; err != nil {
		t.Fatalf("count DB access: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected DB access to be hidden by soft delete, count=%d", count)
	}

	var deleted models.SelfDBAccess
	if err := db.Unscoped().Where("id = ?", access.ID).First(&deleted).Error; err != nil {
		t.Fatalf("find soft-deleted DB access: %v", err)
	}
	if !deleted.DeletedAt.Valid {
		t.Fatal("expected DB access deleted_at to be set")
	}
}

func TestDelDBAccess_MissingAndNotFoundAreErrors(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := DelDBAccess(db, user, nil); err == nil {
		t.Fatal("expected missing ID error")
	}
	if err := DelDBAccess(db, user, []string{"--id", uuid.NewString()}); err == nil {
		t.Fatal("expected not-found error")
	}
}
