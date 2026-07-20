package account

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/sshkey"
	"goBastion/internal/utils/validation"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// CreateDBIngressKey validates and persists an SSH ingress public key for a user.
func CreateDBIngressKey(db *gorm.DB, user *models.User, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("public SSH key cannot be empty")
	}

	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil || pub == nil {
		return fmt.Errorf("invalid SSH key: %s", err)
	}

	sha256Fingerprint := sha256.Sum256(pub.Marshal())
	fingerprint := base64.StdEncoding.EncodeToString(sha256Fingerprint[:])
	keySize := sshkey.GetKeySize(pub)

	if pub.Type() == "ssh-rsa" && keySize < 2048 {
		return fmt.Errorf("RSA key size must be at least 2048 bits (got %d)", keySize)
	}

	var existingKey models.IngressKey
	if err = db.Where("user_id = ? AND fingerprint = ?", user.ID, fingerprint).First(&existingKey).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return validation.WrapDBError(err, "error checking for existing ingress key")
		}
	} else {
		return fmt.Errorf("key already exists with fingerprint: %s", fingerprint)
	}

	ingressKey := models.IngressKey{
		UserID:      user.ID,
		Type:        pub.Type(),
		Key:         key,
		Fingerprint: fingerprint,
		Size:        keySize,
		Comment:     comment,
	}
	if err = db.Create(&ingressKey).Error; err != nil {
		return fmt.Errorf("error creating ingress key in DB: %w", err)
	}
	return nil
}
