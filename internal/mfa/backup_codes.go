package mfa

import (
	"fmt"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/utils/totp"
)

const backupCodeConsumeAttempts = 3

// VerifyAndConsumeBackupCode atomically verifies and removes one of user's backup codes.
func VerifyAndConsumeBackupCode(db *gorm.DB, user *models.User, code string) (bool, error) {
	if db == nil || user == nil {
		return false, fmt.Errorf("consume backup code: database and user are required")
	}

	for range backupCodeConsumeAttempts {
		original := user.BackupCodes
		matched, updated, err := totp.VerifyAndConsumeBackupCode(code, original)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}

		result := db.Model(&models.User{}).
			Where("id = ? AND backup_codes = ?", user.ID, original).
			Update("backup_codes", updated)
		if result.Error != nil {
			return false, fmt.Errorf("consume backup code: %w", result.Error)
		}
		if result.RowsAffected == 1 {
			user.BackupCodes = updated
			return true, nil
		}

		var refreshed models.User
		if err := db.Select("backup_codes").First(&refreshed, "id = ?", user.ID).Error; err != nil {
			return false, fmt.Errorf("reload backup codes: %w", err)
		}
		user.BackupCodes = refreshed.BackupCodes
	}

	return false, fmt.Errorf("consume backup code: concurrent updates exceeded retry limit")
}
