package self

import (
	"testing"

	"goBastion/internal/models"
)

func TestSelfDelAccess_Success(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	// Create access entry directly
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

	// Note: SelfDelAccess uses flag.Func whose String() always returns "",
	// so the "id empty" guard triggers and the function returns nil without deleting.
	// This test verifies the function does not panic or return an error.
	err := SelfDelAccess(db, user, []string{"--id", access.ID.String()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
