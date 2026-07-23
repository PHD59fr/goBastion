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

	// Prevent locking the last remaining admin.
	if u.IsAdmin() {
		var adminCount int64
		if err := db.Model(&models.User{}).Where("role = ? AND deleted_at IS NULL", models.RoleAdmin).Count(&adminCount).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Expire",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to check admin count."}}},
			})
			return err
		}
		if adminCount <= 1 {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Expire",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Blocked", Body: []string{"Cannot lock the last remaining admin account."}}},
			})
			return fmt.Errorf("cannot lock the last remaining admin account")
		}
	}

	if err := db.Model(&u).Update("enabled", false).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Expire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to lock user account."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Expire",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("User '%s' has been locked immediately.", username),
			"The account is now disabled and all active sessions will be terminated on next sync.",
			"Use accountUnexpire --user <username> to re-enable.",
		}}},
	})

	return nil
}
