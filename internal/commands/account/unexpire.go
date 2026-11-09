package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// Unexpire re-enables a disabled account and resets its LastLoginAt.
func Unexpire(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountUnexpire", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to re-enable")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountUnexpire --user <username>"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountUnexpire --user <username>"}}},
		})
		return fmt.Errorf("missing required arguments")
	}

	if !currentUser.CanDo(db, "accountUnexpire", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to re-enable this account."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", username)}}},
		})
		return err
	}

	if u.Enabled {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "warning",
			Sections:  []console.SectionContent{{SubTitle: "Already Active", Body: []string{fmt.Sprintf("User '%s' is already enabled.", username)}}},
		})
		return fmt.Errorf("user %q is already enabled", username)
	}

	if err := withAccountChange(db, func(tx *gorm.DB) error {
		var fresh models.User
		if err := tx.First(&fresh, "id = ?", u.ID).Error; err != nil {
			return err
		}
		if fresh.Enabled {
			return fmt.Errorf("account already enabled")
		}
		result := tx.Model(&fresh).Where("enabled = ?", false).Updates(map[string]any{"enabled": true, "last_login_at": time.Time{}, "last_login_from": ""})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("account changed while being enabled")
		}
		return nil
	}); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to re-enable user account."}}},
		})
		return err
	}

	if err := syncModifiedAccount(u.Username); err != nil {
		return fmt.Errorf("account enabled but privileged reconciliation failed: %w", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Unexpire",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("User '%s' has been re-enabled.", username),
			"Last login history has been cleared.",
		}}},
	})

	return nil
}
