package self

import (
	"fmt"
	"log/slog"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// ChangePassword changes the user's password MFA, verifying the current password first.
func ChangePassword(db *gorm.DB, user *models.User, log *slog.Logger, args []string) error {
	if user.PasswordHash == "" {
		console.DisplayBlock(console.ContentBlock{
			Title: "Change Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"No password MFA configured. Use selfSetPassword first."}}},
		})
		return nil
	}
	fmt.Print("Enter current password: ")
	current, err := readPassword()
	if err != nil {
		return fmt.Errorf("could not read password: %w", err)
	}
	fmt.Println()
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		log.Warn("password_mfa_change_denied", slog.String("user", user.Username), slog.String("reason", "wrong_current_password"))
		console.DisplayBlock(console.ContentBlock{
			Title: "Change Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Current password is incorrect."}}},
		})
		return nil
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
			Title: "Change Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Passwords do not match."}}},
		})
		return nil
	}
	if len(pass1) < 8 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Change Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Password must be at least 8 characters."}}},
		})
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass1), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt error: %w", err)
	}
	if err := db.Model(user).Update("password_hash", string(hash)).Error; err != nil {
		return fmt.Errorf("failed to save password: %w", err)
	}
	user.PasswordHash = string(hash)
	log.Info("password_mfa_changed", slog.String("user", user.Username))
	console.DisplayBlock(console.ContentBlock{
		Title: "Change Password MFA", BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password updated."}}},
	})
	return nil
}
