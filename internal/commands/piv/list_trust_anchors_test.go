package piv

import (
	"testing"

	"goBastion/internal/models"
)

func TestListTrustAnchors_Empty(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := ListTrustAnchors(db, admin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListTrustAnchors_WithData(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Seed two trust anchors directly via DB.
	for _, name := range []string{"yubico", "nexus"} {
		a := models.PIVTrustAnchor{
			Name:      name,
			CertPEM:   "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
			AddedByID: admin.ID,
		}
		if err := db.Create(&a).Error; err != nil {
			t.Fatalf("seed anchor %s: %v", name, err)
		}
	}

	err := ListTrustAnchors(db, admin, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.PIVTrustAnchor{}).Count(&count)
	if count != 2 {
		t.Fatalf("expected 2 anchors in DB, got %d", count)
	}
}
