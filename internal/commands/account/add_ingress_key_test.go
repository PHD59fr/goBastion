package account

import (
	"testing"

	"goBastion/internal/models"
)

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
	err := CreateDBIngressKey(db, user, testPubKey)
	if err == nil {
		t.Fatal("expected error on duplicate key, got nil")
	}
}
