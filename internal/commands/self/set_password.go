package self

import (
	"fmt"
	"log/slog"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SelfSetPassword sets a password-based MFA second factor for the current user.
// The password is stored as a bcrypt hash. It will be required at every login in addition to key auth.
func SelfSetPassword(db *gorm.DB, user *models.User, log *slog.Logger, args []string) error {
	fmt.Print("Enter new password: ")
	pass1, err := readPassword()
	if err != nil {
		return fmt.Errorf("could not read password: %v", err)
	}
	fmt.Print("\nConfirm new password: ")
	pass2, err := readPassword()
	if err != nil {
		return fmt.Errorf("could not read password: %v", err)
	}
	fmt.Println()
	if pass1 != pass2 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Passwords do not match."}}},
		})
		return nil
	}
	if len(pass1) < 8 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Password must be at least 8 characters."}}},
		})
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass1), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt error: %v", err)
	}
	if err := db.Model(user).Update("password_hash", string(hash)).Error; err != nil {
		return fmt.Errorf("failed to save password: %v", err)
	}
	user.PasswordHash = string(hash)
	log.Info("password mfa set", slog.String("user", user.Username))
	console.DisplayBlock(console.ContentBlock{
		Title: "Set Password MFA", BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA configured. It will be required at every login."}}},
	})
	return nil
}
