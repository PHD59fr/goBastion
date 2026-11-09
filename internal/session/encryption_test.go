package session

import (
	"goBastion/internal/utils/cryptokey"
	"os"
	"testing"
)

// This key exists only in tests. Production always requires deployment secrets.
func TestMain(m *testing.M) {
	_ = os.Setenv("EGRESS_ENC_KEY", "PvHlWvN638cmg6oz6ixYa/gsYFNBqD6K1d87+A+8DMo=")
	for _, name := range []string{"EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEY_ID", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE"} {
		_ = os.Unsetenv(name)
	}
	os.Exit(m.Run())
}

func encryptedFixture(t *testing.T, plaintext string) string {
	t.Helper()
	ciphertext, err := cryptokey.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}
