package commands

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"goBastion/models"
	"goBastion/utils/console"
	"goBastion/utils/totp"

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

	console.DisplayBlock(console.ContentBlock{
		Title:     "Setup TOTP",
		BlockType: "info",
		Sections: []console.SectionContent{
			{SubTitle: "Secret (keep safe)", Body: []string{secret}},
			{SubTitle: "Add to your authenticator app", Body: []string{url}},
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
		console.DisplayBlock(console.ContentBlock{
			Title:     "Setup TOTP",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid code — TOTP was NOT enabled. Try again."}},
			},
		})
		return nil
	}

	user.TOTPSecret = secret
	user.TOTPEnabled = true
	if err := db.Save(user).Error; err != nil {
		return fmt.Errorf("failed to save TOTP settings: %w", err)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Setup TOTP",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"TOTP is now enabled on your account."}},
		},
	})
	return nil
}

// SelfDisableTOTP verifies the current TOTP code before disabling it, preventing a stolen
// session from silently removing MFA.
func SelfDisableTOTP(db *gorm.DB, user *models.User) error {
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
		console.DisplayBlock(console.ContentBlock{
			Title:     "Disable TOTP",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid code — TOTP not disabled."}},
			},
		})
		return nil
	}

	user.TOTPSecret = ""
	user.TOTPEnabled = false
	if err := db.Save(user).Error; err != nil {
		return fmt.Errorf("failed to save TOTP settings: %w", err)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Disable TOTP",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"TOTP has been disabled for your account."}},
		},
	})
	return nil
}

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

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Disable TOTP",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"TOTP disabled for " + username}},
		},
	})
	return nil
}
