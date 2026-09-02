package account

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// DisablePassword clears a user's password-based MFA (admin only).
func DisablePassword(db *gorm.DB, currentUser *models.User, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("accountDisablePassword", flag.ContinueOnError)
	var targetUser string
	var buf bytes.Buffer
	fs.StringVar(&targetUser, "user", "", "Target username")
	fs.SetOutput(&buf)

	parseErr := fs.Parse(args)
	if parseErr != nil || targetUser == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable Account Password MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"accountDisablePassword --user <username>"}}},
		})
		if parseErr != nil {
			return parseErr
		}
		return fmt.Errorf("target username is required")
	}

	if !currentUser.CanDo(db, "accountSetPassword", targetUser) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable Account Password MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only admins can clear password MFA for other users."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var user models.User
	if err := db.Where("username = ?", targetUser).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable Account Password MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", targetUser)}}},
		})
		return err
	}

	if err := db.Model(&user).Update("password_hash", "").Error; err != nil {
		return fmt.Errorf("failed to clear password: %w", err)
	}

	log.Info("password_mfa_cleared",
		slog.String("by", currentUser.Username),
		slog.String("user", targetUser),
	)

	console.DisplayBlock(console.ContentBlock{
		Title:     "Disable Account Password MFA",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA cleared for " + targetUser}}},
	})
	return nil
}
