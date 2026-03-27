package account

import (
	"fmt"
	"strings"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

// SwitchSysRoleUser toggles a user's system role between admin and user.
// Refuses to demote the last remaining admin to prevent lockout.
func SwitchSysRoleUser(db *gorm.DB, adapter osadapter.SystemAdapter, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if u.Role == models.RoleAdmin {
		// Count all admins (not just enabled) to prevent demoting the last one.
		var adminCount int64
		if err := db.Model(&models.User{}).Where("role = ? AND deleted_at IS NULL", models.RoleAdmin).Count(&adminCount).Error; err != nil {
			return fmt.Errorf("error counting admins: %w", err)
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot demote the last remaining admin")
		}
		u.Role = models.RoleUser
	} else {
		u.Role = models.RoleAdmin
	}
	if err := db.Save(&u).Error; err != nil {
		return fmt.Errorf("error updating user system role: %w", err)
	}
	return adapter.UpdateSudoers(&u)
}
