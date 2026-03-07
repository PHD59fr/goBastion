package account

import (
	"flag"
	"fmt"
	"log/slog"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// AccountDisableTOTP lets an admin force-disable TOTP for a user (e.g. lost phone).
func AccountDisableTOTP(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountDisableTOTP", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username whose TOTP to disable")
	if err := fs.Parse(args); err != nil || strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Disable TOTP",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"accountDisableTOTP --user <username>"}},
			},
		})
		return nil
	}

	var target models.User
	if err := db.Where("username = ?", username).First(&target).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Disable TOTP",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"User not found: " + username}},
			},
		})
		return err
	}

	target.TOTPSecret = ""
	target.TOTPEnabled = false
	if err := db.Save(&target).Error; err != nil {
		return fmt.Errorf("failed to save: %w", err)
	}

	slog.Default().Info("totp admin-disabled", slog.String("target", username), slog.String("by", currentUser.Username))
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Disable TOTP",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"TOTP disabled for " + username}},
		},
	})
	return nil
}
