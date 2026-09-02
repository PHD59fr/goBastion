package self

import (
	"strings"
	"testing"

	"goBastion/internal/models"
)

const ingressTestPubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test-key"

func TestAddIngressKey_InvalidKeyNoArgs(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := AddIngressKey(db, user, nil); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestAddIngressKey_RejectsNegativeExpiryBeforeInsert(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := AddIngressKey(db, user, []string{"--key", ingressTestPubKey, "--expires", "-1"}); err == nil || !strings.Contains(err.Error(), "cannot be negative") {
		t.Fatalf("expected negative expiry error, got %v", err)
	}

	var count int64
	if err := db.Model(&models.IngressKey{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count ingress keys: %v", err)
	}
	if count != 0 {
		t.Fatalf("found %d ingress keys after validation failure, want 0", count)
	}
}
