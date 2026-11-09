package dbConnector

import (
	"goBastion/internal/utils/cryptokey"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.Setenv("EGRESS_ENC_KEY", "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo=")
	for _, name := range []string{"EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE", "EGRESS_ENC_KEY_ID"} {
		_ = os.Unsetenv(name)
	}
	os.Exit(m.Run())
}
func encryptedDBFixture(t *testing.T, raw string) string {
	t.Helper()
	v, e := cryptokey.Encrypt(raw)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
