package commands

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"goBastion/utils/sync"
	"strings"

	"goBastion/utils/sshkey"
	"goBastion/utils/system"

	"goBastion/models"

	"golang.org/x/crypto/ssh"

	"gorm.io/gorm"
)

func CreateUser(db *gorm.DB, username string, pubKey string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	var userCount int64

	err := db.Model(&models.User{}).Where("username = ? AND deleted_at IS NULL", username).Count(&userCount).Error
	if err != nil {
		return fmt.Errorf("error querying database: %s", err)
	}
	if userCount > 0 {
		return fmt.Errorf("user '%s' already exists", username)
	}

	newUser, err := createDBUser(db, username)
	if err != nil {
		return err
	}

	err = CreateDBIngressKey(db, newUser, pubKey)
	if err != nil {
		return err
	}

	err = sync.CreateUserFromDB(db, *newUser)
	if err != nil {
		return err
	}
	return nil
}

func DeleteUser(db *gorm.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if err := deleteDBUser(db, username); err != nil {
		return err
	}

	if err := system.DeleteUser(username); err != nil {
		return err
	}

	return nil
}

func deleteDBUser(db *gorm.DB, username string) error {
	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if err := db.Delete(&user).Error; err != nil {
		return fmt.Errorf("error deleting user: %w", err)
	}
	return nil
}

func createDBUser(db *gorm.DB, username string) (*models.User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	var existingUser models.User
	result := db.Unscoped().Where("username = ? AND deleted_at IS NULL", username).First(&existingUser)

	if result.Error == nil {
		fmt.Printf("Username '%s' already exists.\n", username)
		return &existingUser, nil
	} else if result.Error != nil && !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("error checking user existence: %v", result.Error)
	}

	newUser := models.User{
		Username: username,
		Role:     "user",
	}
	if err := db.Create(&newUser).Error; err != nil {
		return nil, err
	}
	return &newUser, nil
}

func SwitchRoleUser(db *gorm.DB, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		fmt.Println("Usage: switchRoleUser <username>")
		return nil
	}
	var checkUser models.User
	if err := db.Where("username = ?", username).First(&checkUser).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if checkUser.Role == "admin" {
		checkUser.Role = "user"
	} else {
		checkUser.Role = "admin"
	}

	if err := db.Save(&checkUser).Error; err != nil {
		return fmt.Errorf("error updating user role: %w", err)
	}

	if err := system.UpdateSudoers(&checkUser); err != nil {
		return fmt.Errorf("error updating sudoers: %w", err)
	}

	return nil
}

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
