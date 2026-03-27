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

// AccountSetPassword sets or clears a password MFA second factor for a user account (admin only).
func AccountSetPassword(db *gorm.DB, currentUser *models.User, log *slog.Logger, args []string) error {
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
		return nil
	}

	if !currentUser.CanDo(db, "accountSetPassword", targetUser) {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only admins can set password MFA for other users."}}},
		})
		return nil
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
			return fmt.Errorf("failed to clear password: %v", err)
		}
		log.Info("password mfa cleared by admin",
			slog.String("admin", currentUser.Username),
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
		return fmt.Errorf("could not read password: %v", err)
	}
	passStr := string(passBytes)
	if len(passStr) < 8 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Password must be at least 8 characters."}}},
		})
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(passStr), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt error: %v", err)
	}
	if err := db.Model(&user).Update("password_hash", string(hash)).Error; err != nil {
		return fmt.Errorf("failed to save password: %v", err)
	}
	log.Info("password mfa set by admin",
		slog.String("admin", currentUser.Username),
		slog.String("user", targetUser),
	)
	console.DisplayBlock(console.ContentBlock{
		Title: "Set Account Password MFA", BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA set for " + targetUser}}},
	})
	return nil
}
