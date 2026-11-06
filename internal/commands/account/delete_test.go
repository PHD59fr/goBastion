package account

import (
	"errors"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

func TestDeleteUser_Success(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	newRegularUser(t, db, "bob")

	if err := DeleteUser(db, mock, "bob"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should be soft-deleted
	var count int64
	db.Model(&models.User{}).Where("username = ?", "bob").Count(&count)
	if count != 0 {
		t.Fatal("expected user to be soft-deleted")
	}

	// Adapter should record deletion
	found := false
	for _, u := range mock.DeletedUsers {
		if u == "bob" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected 'bob' in mock.DeletedUsers, got %v", mock.DeletedUsers)
	}
}

func TestDeleteUser_NotFound(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	err := DeleteUser(db, mock, "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent user, got nil")
	}
}

func TestDeleteUser_AdapterError(t *testing.T) {
	db := newTestDB(t)
	mock := osadapter.NewMockAdapter()
	mock.ErrDeleteUser = errors.New("os delete failed")
	newRegularUser(t, db, "carol")

	err := DeleteUser(db, mock, "carol")
	if err == nil {
		t.Fatal("expected error from adapter, got nil")
	}

	var count int64
	if err := db.Model(&models.User{}).Where("username = ?", "carol").Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("OS failure must restore the active database account")
	}
}

func TestDelete_MissingUsernameIsError(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	if err := Delete(db, osadapter.NewMockAdapter(), admin, nil); err == nil {
		t.Fatal("expected missing username error")
	}
}
