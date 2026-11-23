package sshkey

import "errors"

// ValidateGenerationSize limits the work requested from ssh-keygen in a
// session. The caller separately allowlists the key type.
func ValidateGenerationSize(keyType string, size int) error {
	switch keyType {
	case "rsa":
		if size >= 2048 && size <= 8192 {
			return nil
		}
	case "ecdsa":
		if size == 256 || size == 384 || size == 521 {
			return nil
		}
	case "ed25519":
		if size == 256 {
			return nil
		}
	}
	return errors.New("invalid SSH key size for selected type")
}
