package mfa

import (
	"fmt"

	"goBastion/internal/models"

	"gorm.io/gorm"
)

// Only MFA fields are written. Concurrent role changes must never be reverted.
func UpdateTOTP(db *gorm.DB, u *models.User) *gorm.DB {
	result := db.Model(&models.User{}).Where("id = ? AND enabled = ?", u.ID, true).Updates(map[string]any{"totp_secret": u.TOTPSecret, "totp_enabled": u.TOTPEnabled, "backup_codes": u.BackupCodes})
	if result.Error == nil && result.RowsAffected != 1 {
		result.Error = fmt.Errorf("account was revoked or removed during MFA setup")
	}
	return result
}
