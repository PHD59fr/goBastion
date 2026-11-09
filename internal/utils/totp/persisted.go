package totp

import "goBastion/internal/utils/cryptokey"

// VerifyStoredSecret verifies a persisted TOTP secret only after authenticated
// decryption. Enrollment must use Verify with its newly generated raw secret.
func VerifyStoredSecret(ciphertext, code string) bool {
	secret, err := cryptokey.Decrypt(ciphertext)
	if err != nil || secret == "" {
		return false
	}
	return Verify(secret, code)
}
