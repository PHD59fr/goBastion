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
	var fresh models.User
	if err := db.Select("id", "totp_secret").Where("id = ? AND enabled = ?", u.ID, true).First(&fresh).Error; err != nil {
		result := db.Session(&gorm.Session{})
		_ = result.AddError(fmt.Errorf("account unavailable during MFA setup: %w", err))
		return result
	}
	updates := map[string]any{"totp_secret": storedSecret, "totp_enabled": u.TOTPEnabled, "backup_codes": u.BackupCodes}
	// Reset replay state only for a different underlying seed. Re-encrypting the
	// same seed must not make an already consumed code usable again.
	changed := storedSecret != fresh.TOTPSecret
	if changed && storedSecret != "" && fresh.TOTPSecret != "" {
		before, beforeErr := cryptokey.Decrypt(fresh.TOTPSecret)
		after, afterErr := cryptokey.Decrypt(storedSecret)
		changed = beforeErr != nil || afterErr != nil || before != after
	}
	if changed {
		updates["totp_last_step"] = 0
	}
	result := db.Model(&models.User{}).Where("id = ? AND enabled = ? AND COALESCE(totp_secret, '') = ?", u.ID, true, fresh.TOTPSecret).Updates(updates)
	if result.Error == nil && result.RowsAffected != 1 {
		result.Error = fmt.Errorf("account was revoked or removed during MFA setup")
	}
	return result
}
