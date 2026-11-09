package sftpProxy

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("EGRESS_ENC_KEY", "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo=")
	for _, n := range []string{"EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE", "EGRESS_ENC_KEY_ID"} {
		_ = os.Unsetenv(n)
	}
	os.Exit(m.Run())
}
