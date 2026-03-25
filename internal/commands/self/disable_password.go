package self

import (
	"fmt"
	"log/slog"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// SelfDisablePassword lets a user disable their password-based MFA after verifying the current password.
func SelfDisablePassword(db *gorm.DB, user *models.User, args []string) error {
	if user.PasswordHash == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable Password MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"No password MFA configured."}}},
		})
		return nil
	}

	fmt.Print("Enter current password: ")
	current, err := readPassword()
	if err != nil {
		return fmt.Errorf("could not read password: %v", err)
	}
	fmt.Println()

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)) != nil {
		slog.Default().Warn("password mfa disable denied - wrong current password", slog.String("user", user.Username))
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable Password MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Current password is incorrect."}}},
		})
		return nil
	}

	if err := db.Model(user).Update("password_hash", "").Error; err != nil {
		return fmt.Errorf("failed to clear password: %v", err)
	}
	user.PasswordHash = ""
	slog.Default().Info("password mfa disabled", slog.String("user", user.Username))
	console.DisplayBlock(console.ContentBlock{
		Title:     "Disable Password MFA",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA has been disabled for your account."}}},
	})
	return nil
}
