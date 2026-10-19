package account

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"goBastion/internal/models"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func TestCreateDBIngressKey_GeneratedKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		pub  any
		size int
	}{
		{"rsa4096", &rsaKey.PublicKey, 4096},
		{"ed25519", edKey, 256},
	} {
		key, err := ssh.NewPublicKey(tt.pub)
		if err != nil {
			t.Fatal(err)
		}
		for _, comment := range []string{"", "user@laptop with spaces"} {
			t.Run(tt.name+"/"+comment, func(t *testing.T) {
				db := newTestDB(t)
				user := newRegularUser(t, db, "alice")
				text := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
				if comment != "" {
					text += " " + comment
				}
				if err := CreateDBIngressKey(db, user, text); err != nil {
					t.Fatal(err)
				}
				var stored models.IngressKey
				if err := db.Where("user_id = ?", user.ID).First(&stored).Error; err != nil {
					t.Fatal(err)
				}
				if stored.Key != text || stored.Type != key.Type() || stored.Size != tt.size || stored.Comment != comment {
					t.Fatalf("incorrect stored key: %+v", stored)
				}
			})
		}
	}
}

func TestCreateDBIngressKey_RejectsWeakRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	err = CreateDBIngressKey(db, user, string(ssh.MarshalAuthorizedKey(key)))
	if err == nil || !strings.Contains(err.Error(), "at least 2048 bits") {
		t.Fatalf("expected weak RSA rejection, got %v", err)
	}
	var count int64
	if err := db.Model(&models.IngressKey{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stored %d keys after weak RSA rejection", count)
	}
}

func TestCreateDBIngressKey_Valid(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := CreateDBIngressKey(db, user, testPubKey); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var key models.IngressKey
	if err := db.Where("user_id = ?", user.ID).First(&key).Error; err != nil {
		t.Fatalf("key not found in DB: %v", err)
	}
	if key.Fingerprint == "" {
		t.Fatal("expected non-empty fingerprint")
	}
}

func TestCreateDBIngressKey_StoresMetadataOnInsert(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	expiresAt := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

	if err := CreateDBIngressKey(db, user, testPubKey, IngressKeyMetadata{
		ExpiresAt:   &expiresAt,
		PIVAttested: true,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var key models.IngressKey
	if err := db.Where("user_id = ?", user.ID).First(&key).Error; err != nil {
		t.Fatalf("key not found in DB: %v", err)
	}
	if key.ExpiresAt == nil || !key.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expires_at = %v, want %v", key.ExpiresAt, expiresAt)
	}
	if !key.PIVAttested {
		t.Fatal("expected key to be PIV-attested")
	}
}

func TestCreateDBIngressKey_InsertFailureLeavesNoKey(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	insertErr := errors.New("injected ingress key insert failure")
	const callbackName = "test:fail_ingress_key_insert"
	if err := db.Callback().Create().Before("gorm:create").Register(callbackName, func(tx *gorm.DB) {
		if _, ok := tx.Statement.Dest.(*models.IngressKey); ok {
			_ = tx.AddError(insertErr)
		}
	}); err != nil {
		t.Fatalf("register create callback: %v", err)
	}
	t.Cleanup(func() { _ = db.Callback().Create().Remove(callbackName) })

	expiresAt := time.Now().Add(24 * time.Hour)
	err := CreateDBIngressKey(db, user, testPubKey, IngressKeyMetadata{
		ExpiresAt:   &expiresAt,
		PIVAttested: true,
	})
	if !errors.Is(err, insertErr) {
		t.Fatalf("expected insert error to propagate, got %v", err)
	}

	var count int64
	if err := db.Model(&models.IngressKey{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count ingress keys: %v", err)
	}
	if count != 0 {
		t.Fatalf("found %d ingress keys after failed insert, want 0", count)
	}
}

func TestCreateDBIngressKey_Empty(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	err := CreateDBIngressKey(db, user, "")
	if err == nil {
		t.Fatal("expected error for empty key, got nil")
	}
}

func TestCreateDBIngressKey_Invalid(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	err := CreateDBIngressKey(db, user, "not-a-valid-ssh-key garbage!!!")
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
}

func TestCreateDBIngressKey_Duplicate(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := CreateDBIngressKey(db, user, testPubKey); err != nil {
		t.Fatalf("unexpected error on first insert: %v", err)
	}
	duplicateKey := strings.Replace(testPubKey, "test-key", "different-comment", 1)
	err := CreateDBIngressKey(db, user, duplicateKey, IngressKeyMetadata{PIVAttested: true})
	if err == nil || !strings.Contains(err.Error(), "key already exists with fingerprint") {
		t.Fatalf("expected duplicate fingerprint error, got %v", err)
	}

	var count int64
	if err := db.Model(&models.IngressKey{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count ingress keys: %v", err)
	}
	if count != 1 {
		t.Fatalf("found %d ingress keys after duplicate insert, want 1", count)
	}
}
