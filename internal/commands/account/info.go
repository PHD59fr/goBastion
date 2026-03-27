package account

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// AccountInfo displays detailed information for a specific user account.
func AccountInfo(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountInfo", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to display information")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Missing required argument for -user flag. Please specify a username."}},
			},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		err := errors.New("missing required argument for -user flag. Please specify a username")
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{err.Error()}},
			},
		})
		return err
	}

	if !currentUser.CanDo(db, "accountInfo", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to view this account's information."}},
			},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"User \"" + username + "\" not found. Check spelling or run accountList."}},
			},
		})
		return err
	}
	var userGroups []models.UserGroup
	if err := db.Preload("Group").Where("user_id = ?", user.ID).Find(&userGroups).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{fmt.Sprintf("Error loading user groups: %v", err)}},
			},
		})
		return err
	}

	totpStatus := "❌ Disabled"
	if user.TOTPEnabled {
		totpStatus = "✅ Enabled"
	}
	passwordMFAStatus := "❌ Not set"
	if user.PasswordHash != "" {
		passwordMFAStatus = "✅ Set"
	}
	infoLines := []string{
		fmt.Sprintf("ID: %s", user.ID.String()),
		fmt.Sprintf("Username: %s", user.Username),
		fmt.Sprintf("System Role: %s", user.Role),
		fmt.Sprintf("MFA / TOTP: %s", totpStatus),
		fmt.Sprintf("MFA / Password: %s", passwordMFAStatus),
		fmt.Sprintf("Created At: %s", user.CreatedAt.Format("2006-01-02 15:04:05")),
		fmt.Sprintf("Last Login: %s", user.LastLoginAt),
		fmt.Sprintf("Last Login From: %s", user.LastLoginFrom),
		"Groups:",
	}

	if len(userGroups) == 0 {
		infoLines = append(infoLines, "User isn't a member of any groups. 😭")
	} else {
		for _, ug := range userGroups {

			role := utils.GetRoles(ug)
			var coloredRole string
			switch role {
			case "Owner":
				coloredRole = utils.BgRedB("Owner")
			case "ACL Keeper":
				coloredRole = utils.BgYellowB("ACL Keeper")
			case "Gate Keeper":
				coloredRole = utils.BgGreenB("Gate Keeper")
			default:
				coloredRole = utils.BgBlueB("Member")
			}

			infoLines = append(infoLines, fmt.Sprintf(" - %s - %s", ug.Group.Name, coloredRole))
		}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Info",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "User Information", Body: infoLines},
		},
	})
	return nil
}
