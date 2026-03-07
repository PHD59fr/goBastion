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

	"github.com/mdp/qrterminal/v3"
	"gorm.io/gorm"
)

// SelfSetupTOTP generates a TOTP secret, shows the enrollment URL, and asks the user to
// confirm a code before persisting. This ensures the authenticator app is correctly set up.
func SelfSetupTOTP(db *gorm.DB, user *models.User) error {
	if user.TOTPEnabled {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Setup TOTP",
			BlockType: "warning",
			Sections: []console.SectionContent{
				{SubTitle: "Warning", Body: []string{"TOTP is already enabled. Running this will replace your existing TOTP secret."}},
			},
		})
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return fmt.Errorf("failed to generate TOTP secret: %w", err)
	}

	url := totp.OtpAuthURL("goBastion", user.Username, secret)

	// Print QR code directly to terminal (half-block mode = half the size)
	fmt.Println()
	qrterminal.GenerateWithConfig(url, qrterminal.Config{
		Level:          qrterminal.L,
		Writer:         os.Stdout,
		BlackChar:      qrterminal.BLACK_BLACK,
		WhiteChar:      qrterminal.WHITE_WHITE,
		BlackWhiteChar: qrterminal.BLACK_WHITE,
		WhiteBlackChar: qrterminal.WHITE_BLACK,
		QuietZone:      1,
		HalfBlocks:     true,
	})
	fmt.Println()

	console.DisplayBlock(console.ContentBlock{
		Title:     "Setup TOTP",
		BlockType: "info",
		Sections: []console.SectionContent{
			{SubTitle: "Or enter secret manually in your authenticator app", Body: []string{secret}},
			{SubTitle: "OTP Auth URL", Body: []string{url}},
		},
	})

	fmt.Print("Enter the 6-digit code from your authenticator to confirm: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading confirmation code: %w", err)
	}
	code = strings.TrimSpace(code)

	if !totp.Verify(secret, code) {
		slog.Default().Warn("totp setup failed - bad confirmation code", slog.String("user", user.Username))
		console.DisplayBlock(console.ContentBlock{
			Title:     "Setup TOTP",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid code - TOTP was NOT enabled. Try again."}},
			},
		})
		return nil
	}

	user.TOTPSecret = secret
	user.TOTPEnabled = true
	if err := db.Save(user).Error; err != nil {
		return fmt.Errorf("failed to save TOTP settings: %w", err)
	}

	slog.Default().Info("totp enabled", slog.String("user", user.Username))
	console.DisplayBlock(console.ContentBlock{
		Title:     "Setup TOTP",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"TOTP is now enabled on your account."}},
		},
	})
	return nil
}
