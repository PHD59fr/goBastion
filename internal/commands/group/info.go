package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// Info displays detailed information about a group.
func Info(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupInfo", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupInfo --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupInfo", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view group information."}}},
		})
		return fmt.Errorf("access denied for user %s", currentUser.Username)
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
		})
		return err
	}

	var userGroups []models.UserGroup
	if err := db.Preload("User").Where("group_id = ?", g.ID).Find(&userGroups).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to load group members."}}},
		})
		return err
	}

	infoLines := []string{
		fmt.Sprintf("Group ID: %s", g.ID.String()),
		fmt.Sprintf("Name: %s", g.Name),
		fmt.Sprintf("JIT MFA: %s", map[bool]string{true: "✅ Required", false: "❌ Not required"}[g.MFARequired]),
	}

	if len(userGroups) > 0 {
		infoLines = append(infoLines, "Members:")
		for _, ug := range userGroups {
			roleColored := utils.RoleColor(ug)

			infoLines = append(infoLines, fmt.Sprintf(" - %s - %s", ug.User.Username, roleColored))
		}
	} else {
		infoLines = append(infoLines, "Members: None")
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Info",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Details", Body: infoLines}},
	})
	return nil
}
