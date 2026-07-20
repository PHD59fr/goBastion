package piv

import (
	"os"
	"path/filepath"
	"testing"

	"goBastion/internal/models"
)

func TestAddTrustAnchor_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Create a temporary PEM certificate file.
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"), 0644); err != nil {
		t.Fatalf("write temp cert: %v", err)
	}

	err := AddTrustAnchor(db, admin, []string{
		"--name", "yubico-ca",
		"--cert", certPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var a models.PIVTrustAnchor
	if err := db.Where("name = ?", "yubico-ca").First(&a).Error; err != nil {
		t.Fatalf("trust anchor not found in DB: %v", err)
	}
	if a.CertPEM == "" {
		t.Fatal("expected CertPEM to be non-empty")
	}
}

func TestAddTrustAnchor_PermissionDenied(t *testing.T) {
	db := newTestDB(t)
	regular := newRegularUser(t, db, "regular")

	// The pivAddTrustAnchor permission requires admin, super_owner, or a grant.
	if regular.CanDo(db, "pivAddTrustAnchor", "") {
		t.Fatal("expected regular user to lack pivAddTrustAnchor permission")
	}
}

func TestAddTrustAnchor_MissingArgs(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Missing --cert flag triggers usage error.
	err := AddTrustAnchor(db, admin, []string{"--name", "myca"})
	if err != nil {
		t.Fatalf("expected nil (usage error), got: %v", err)
	}

	var count int64
	db.Model(&models.PIVTrustAnchor{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected no trust anchor created, got %d", count)
	}
}
