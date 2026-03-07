package account

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/sshkey"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// CreateDBIngressKey validates and persists an SSH ingress public key for a user.
func CreateDBIngressKey(db *gorm.DB, user *models.User, pubKeyStr string) error {
	pubKeyStr = strings.TrimSpace(pubKeyStr)
	if pubKeyStr == "" {
		return fmt.Errorf("public SSH key cannot be empty")
	}

	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil || pubKey == nil {
		return fmt.Errorf("invalid SSH key: %s", err)
	}

	sha256Fingerprint := sha256.Sum256(pubKey.Marshal())
	fingerprint := base64.StdEncoding.EncodeToString(sha256Fingerprint[:])
	keySize := sshkey.GetKeySize(pubKey)

	var existingKey models.IngressKey
	if err = db.Where("user_id = ? AND fingerprint = ?", user.ID, fingerprint).First(&existingKey).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("error checking for existing ingress key: %w", err)
		}
	} else {
		return fmt.Errorf("key already exists with fingerprint: %s", fingerprint)
	}

	ingressKey := models.IngressKey{
		UserID:      user.ID,
		Type:        pubKey.Type(),
		Key:         pubKeyStr,
		Fingerprint: fingerprint,
		Size:        keySize,
		Comment:     comment,
	}
	if err = db.Create(&ingressKey).Error; err != nil {
		return fmt.Errorf("error creating ingress key in DB: %w", err)
	}
	return nil
}
