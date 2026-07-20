package cmdhelper

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func RequirePermission(db *gorm.DB, user *models.User, permission, resource, title string) error {
	if !user.CanDo(db, permission, resource) {
		console.ErrorBlock(title, "Access Denied", fmt.Sprintf("You do not have permission to perform this action on '%s'.", resource))
		return fmt.Errorf("access denied for %s", user.Username)
	}
	return nil
}

func FindGroup(db *gorm.DB, name, title string) (*models.Group, error) {
	var g models.Group
	if err := db.Where("name = ?", name).First(&g).Error; err != nil {
		console.ErrorBlock(title, "Not Found", fmt.Sprintf("Group '%s' not found.", name))
		return nil, err
	}
	return &g, nil
}

func FindUser(db *gorm.DB, username, title string) (*models.User, error) {
	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.ErrorBlock(title, "Not Found", fmt.Sprintf("User '%s' not found.", username))
		return nil, err
	}
	return &u, nil
}

func FindRealm(db *gorm.DB, name, title string) (*models.Realm, error) {
	var r models.Realm
	if err := db.Where("name = ?", name).First(&r).Error; err != nil {
		console.ErrorBlock(title, "Not Found", fmt.Sprintf("Realm '%s' not found.", name))
		return nil, err
	}
	return &r, nil
}

func EnsureNotLastAdmin(db *gorm.DB, title string) error {
	var count int64
	if err := db.Model(&models.User{}).Where("role = ? AND deleted_at IS NULL", models.RoleAdmin).Count(&count).Error; err != nil {
		return fmt.Errorf("error counting admins: %w", err)
	}
	if count <= 1 {
		console.ErrorBlock(title, "Operation Denied", "Cannot demote or remove the last remaining admin.")
		return fmt.Errorf("cannot demote the last remaining admin")
	}
	return nil
}

func ReadInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func ParseUUID(id, title string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		console.ErrorBlock(title, "Invalid UUID", fmt.Sprintf("'%s' is not a valid UUID.", id))
		return uuid.Nil, err
	}
	return parsed, nil
}
