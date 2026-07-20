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
		return nil
	}

	if !currentUser.CanDo(db, "accountUnexpire", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to re-enable this account."}}},
		})
		return nil
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
		return nil
	}

	if err := db.Model(&u).Updates(map[string]any{
		"enabled":        true,
		"last_login_at":  time.Time{},
		"last_login_from": "",
	}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Unexpire",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to re-enable user account."}}},
		})
		return err
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
