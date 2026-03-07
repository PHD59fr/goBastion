package account

import (
	"errors"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

const testPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test-key"

func TestCreateDBUser_Success(t *testing.T) {
	db := newTestDB(t)
	user, err := createDBUser(db, "alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user == nil || user.Username != "alice" {
		t.Fatal("expected user to be created")
	}
	var found models.User
	if err := db.Where("username = ?", "alice").First(&found).Error; err != nil {
		t.Fatalf("user not found in DB: %v", err)
	}
}

func TestCreateDBUser_Duplicate(t *testing.T) {
	db := newTestDB(t)
	// First call creates the user
	if _, err := createDBUser(db, "alice"); err != nil {
		t.Fatalf("unexpected error on first create: %v", err)
	}
	// Second call should return the existing user (no error per implementation)
	user2, err := createDBUser(db, "alice")
	if err != nil {
		t.Fatalf("unexpected error on second create: %v", err)
	}
	// Should return the existing user
	if user2 == nil || user2.Username != "alice" {
		t.Fatal("expected existing user to be returned")
	}
	var count int64
	db.Model(&models.User{}).Where("username = ?", "alice").Count(&count)
	if count != 1 {
		t.Fatalf("expected 1 user, got %d", count)
	}
}

func TestCreateUser_AdapterCalled(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	// CreateUser may fail on IngressKeyFromDB (filesystem ops on /home), but
	// mock.CreateUser is called before the filesystem step, so CreatedUsers is populated.
	_ = CreateUser(db, mock, "alice", testPubKey)
	found := false
	for _, u := range mock.CreatedUsers {
		if u == "alice" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected 'alice' in CreatedUsers, got %v", mock.CreatedUsers)
	}
}

func TestCreateUser_AdapterError(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	mock.ErrCreateUser = errors.New("fail")
	err := CreateUser(db, mock, "alice", testPubKey)
	if err == nil {
		t.Fatal("expected error from adapter, got nil")
	}
}

func TestAccountCreate_MissingArgs(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	admin := newAdminUser(t, db, "admin")
	// Should not panic; missing --user arg
	_ = AccountCreate(db, mock, admin, []string{})
}
