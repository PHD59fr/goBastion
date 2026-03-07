package self

import (
	"testing"
)

func TestSelfAddIngressKey_InvalidKeyNoArgs(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	// No args — should not panic; returns nil (empty key path returns nil)
	_ = SelfAddIngressKey(db, user, []string{})
}
