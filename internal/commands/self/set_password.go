package self

import (
	"fmt"
	"log/slog"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SetPassword sets a password-based MFA second factor for the current user.
// The password is stored as a bcrypt hash. It will be required at every login in addition to key auth.
func SetPassword(db *gorm.DB, user *models.User, log *slog.Logger, args []string) error {
	if user.PasswordHash != "" {
		return fmt.Errorf("password MFA already configured; use selfChangePassword")
	}
	var fresh models.User
	if err := db.First(&fresh, "id = ?", user.ID).Error; err != nil {
		return err
	}
	if fresh.PasswordHash != "" {
		return fmt.Errorf("password MFA already configured; use selfChangePassword")
	}
	fmt.Print("Enter new password: ")
	pass1, err := readPassword()
	if err != nil {
		return fmt.Errorf("could not read password: %w", err)
	}
	fmt.Print("\nConfirm new password: ")
	pass2, err := readPassword()
	if err != nil {
		return fmt.Errorf("could not read password: %w", err)
	}
	fmt.Println()
	if pass1 != pass2 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Passwords do not match."}}},
		})
		return fmt.Errorf("passwords do not match")
	}
	if len(pass1) < 8 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Password must be at least 8 characters."}}},
		})
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass1), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt error: %w", err)
	}
	result := db.Model(&models.User{}).Where(map[string]any{"id": user.ID, "enabled": true, "system_user": false}).Where("password_hash IS NULL OR password_hash = ?", "").Update("password_hash", string(hash))
	if err := result.Error; err != nil {
		return fmt.Errorf("failed to save password: %w", err)
	}
	if result.RowsAffected != 1 {
		return fmt.Errorf("account changed or password already configured; reconnect or use selfChangePassword")
	}
	user.PasswordHash = string(hash)
	log.Info("password_mfa_set", slog.String("user", user.Username))
	console.DisplayBlock(console.ContentBlock{
		Title: "Set Password MFA", BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA configured. It will be required at every login."}}},
	})
	return nil
}
