package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/system"

	"gorm.io/gorm"
)

// AccountModify updates the system role of a user account.
func AccountModify(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountModify", flag.ContinueOnError)
	var username, newRole string
	fs.StringVar(&username, "user", "", "Username to modify")
	fs.StringVar(&newRole, "sysrole", "", "New system role (admin or user)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountModify --user <username> --sysrole <admin|user>"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" || strings.TrimSpace(newRole) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountModify --user <username> --sysrole <admin|user>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountModify", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to modify this account."}}},
		})
		return nil
	}

	newRole = strings.ToLower(newRole)
	if newRole != "admin" && newRole != "user" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid System Role", Body: []string{"System role must be 'admin' or 'user'."}}},
		})
		return nil
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.",username)}}},
		})
		return err
	}

	u.Role = newRole
	if err := db.Save(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to update user system role."}}},
		})
		return err
	}

	_ = system.UpdateSudoers(&u)
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Modify",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' system role updated to '%s'.", username, newRole)}}},
	})

	return nil
}
