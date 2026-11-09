package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// Expire immediately disables a user account (force lock).
// Unlike the automatic inactivity lockout, this is an instant admin action
// for when a collaborator leaves the organisation.
func Expire(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountExpire", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to lock")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Expire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountExpire --user <username>"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Expire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountExpire --user <username>"}}},
		})
		return fmt.Errorf("missing required arguments")
	}

	if !currentUser.CanDo(db, "accountExpire", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Expire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to lock this account."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Expire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", username)}}},
		})
		return err
	}

	if !u.Enabled {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Expire",
			BlockType: "warning",
			Sections:  []console.SectionContent{{SubTitle: "Already Locked", Body: []string{fmt.Sprintf("User '%s' is already disabled.", username)}}},
		})
		return fmt.Errorf("user %q is already disabled", username)
	}

	// Prevent admins from locking themselves out.
	if u.ID == currentUser.ID {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Expire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Blocked", Body: []string{"You cannot lock your own account."}}},
		})
		return fmt.Errorf("cannot lock your own account")
	}

	if err := withAccountChange(db, func(tx *gorm.DB) error {
		var fresh models.User
		if err := tx.First(&fresh, "id = ?", u.ID).Error; err != nil {
			return err
		}
		if err := requireOtherAdmin(tx, &fresh); err != nil {
			return err
		}
		return tx.Model(&fresh).Update("enabled", false).Error
	}); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title: "Account Expire", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Blocked", Body: []string{err.Error()}}},
		})
		return err
	}

	if err := syncModifiedAccount(u.Username); err != nil {
		return fmt.Errorf("account disabled but privileged reconciliation failed: %w", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Expire",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("User '%s' has been locked immediately.", username),
			"The account is disabled; local privileged reconciliation completed.",
			"Use accountUnexpire --user <username> to re-enable.",
		}}},
	})

	return nil
}
