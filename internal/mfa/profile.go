package mfa

import (
	"fmt"

	"goBastion/internal/models"
	"goBastion/internal/utils/cryptokey"

	"gorm.io/gorm"
)

// Only MFA fields are written. Concurrent role changes must never be reverted.
func UpdateTOTP(db *gorm.DB, u *models.User) *gorm.DB {
	// Keep the enrollment secret in memory for its caller; persist only its
	// authenticated ciphertext. A failed encryption must never write plaintext.
	if err := cryptokey.Validate(); err != nil {
		result := db.Session(&gorm.Session{})
		_ = result.AddError(err)
		return result
	}
	storedSecret := ""
	if u.TOTPSecret != "" {
		var err error
		storedSecret, err = cryptokey.ReEncryptIfNeeded(u.TOTPSecret)
		if err != nil {
			result := db.Session(&gorm.Session{})
			_ = result.AddError(err)
			return result
		}
	}
	result := db.Model(&models.User{}).Where("id = ? AND enabled = ?", u.ID, true).Updates(map[string]any{"totp_secret": storedSecret, "totp_enabled": u.TOTPEnabled, "backup_codes": u.BackupCodes})
	if result.Error == nil && result.RowsAffected != 1 {
		result.Error = fmt.Errorf("account was revoked or removed during MFA setup")
	}
	return result
}
