package piv

import (
	"testing"

	"goBastion/internal/models"
)

func TestRemoveTrustAnchor_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	a := models.PIVTrustAnchor{
		Name:      "to-delete",
		CertPEM:   "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
		AddedByID: admin.ID,
	}
	if err := db.Create(&a).Error; err != nil {
		t.Fatalf("seed anchor: %v", err)
	}

	err := RemoveTrustAnchor(db, admin, []string{"--name", "to-delete"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.PIVTrustAnchor{}).Where("name = ?", "to-delete").Count(&count)
	if count != 0 {
		t.Fatalf("expected trust anchor to be deleted, count=%d", count)
	}
}

func TestRemoveTrustAnchor_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Removing a non-existent anchor returns nil.
	err := RemoveTrustAnchor(db, admin, []string{"--name", "nonexistent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
