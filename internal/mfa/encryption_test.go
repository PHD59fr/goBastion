package mfa

import (
	"os"
	"testing"
)

// This key exists only in tests. Production always requires deployment secrets.
func TestMain(m *testing.M) {
	if os.Getenv("GOB_MFA_TEST_MISSING_KEY") == "1" {
		_ = os.Unsetenv("EGRESS_ENC_KEY")
	} else {
		_ = os.Setenv("EGRESS_ENC_KEY", "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo=")
	}
	for _, name := range []string{"EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEY_ID", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE"} {
		_ = os.Unsetenv(name)
	}
	os.Exit(m.Run())
}
