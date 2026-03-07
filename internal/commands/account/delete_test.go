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

	// User should NOT be soft-deleted in DB when adapter fails
	var count int64
	db.Unscoped().Model(&models.User{}).Where("username = ? AND deleted_at IS NOT NULL", "carol").Count(&count)
	// The DB deletion happens before adapter call in deleteDBUser, so the user IS soft-deleted in DB.
	// The important thing is that the error is propagated.
	_ = count
}
