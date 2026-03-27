package totp

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/totp"

	"gorm.io/gorm"
)

// SelfDisableTOTP verifies the current TOTP code before disabling it, preventing a stolen
// session from silently removing MFA.
func SelfDisableTOTP(db *gorm.DB, user *models.User, log *slog.Logger) error {
	if !user.TOTPEnabled {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable TOTP",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"TOTP is not enabled on your account."}},
			},
		})
		return nil
	}

	fmt.Print("Enter your current TOTP code to confirm: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading code: %w", err)
	}
	code = strings.TrimSpace(code)

	if !totp.Verify(user.TOTPSecret, code) {
		log.Warn("totp disable failed - bad code", slog.String("user", user.Username))
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable TOTP",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid code - TOTP not disabled."}},
			},
		})
		return nil
	}

	user.TOTPSecret = ""
	user.TOTPEnabled = false
	if err := db.Save(user).Error; err != nil {
		return fmt.Errorf("failed to save TOTP settings: %w", err)
	}

	log.Info("totp disabled", slog.String("user", user.Username))
	console.DisplayBlock(console.ContentBlock{
		Title:     "Disable TOTP",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"TOTP has been disabled for your account."}},
		},
	})
	return nil
}
