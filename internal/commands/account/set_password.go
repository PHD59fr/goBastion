package account

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gorm.io/gorm"
)

// SetPassword sets or clears a password MFA second factor for a user account (admin only).
func SetPassword(db *gorm.DB, currentUser *models.User, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("accountSetPassword", flag.ContinueOnError)
	var targetUser string
	var clear bool
	fs.StringVar(&targetUser, "user", "", "Target username")
	fs.BoolVar(&clear, "clear", false, "Clear/remove password MFA for the user")
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	if err := fs.Parse(args); err != nil || targetUser == "" {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Usage", Body: []string{"accountSetPassword --user <username> [--clear]"}}},
		})
		if err != nil {
			return err
		}
		return fmt.Errorf("missing required arguments")
	}

	if !currentUser.CanDo(db, "accountSetPassword", targetUser) {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only admins can set password MFA for other users."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var user models.User
	if err := db.Where("username = ?", targetUser).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", targetUser)}}},
		})
		return err
	}

	if clear {
		if err := db.Model(&user).Update("password_hash", "").Error; err != nil {
			return fmt.Errorf("failed to clear password: %w", err)
		}
		log.Info("password_mfa_cleared",
			slog.String("by", currentUser.Username),
			slog.String("user", targetUser),
		)
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "success",
			Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA cleared for " + targetUser}}},
		})
		return nil
	}

	fmt.Print("Enter new password for " + targetUser + ": ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("could not read password: %w", err)
	}
	password := string(passBytes)
	if len(password) < 8 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Password must be at least 8 characters."}}},
		})
		return fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt error: %w", err)
	}
	if err := db.Model(&user).Update("password_hash", string(hash)).Error; err != nil {
		return fmt.Errorf("failed to save password: %w", err)
	}
	log.Info("password_mfa_set",
		slog.String("by", currentUser.Username),
		slog.String("user", targetUser),
	)
	console.DisplayBlock(console.ContentBlock{
		Title: "Set Account Password MFA", BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA set for " + targetUser}}},
	})
	return nil
}
