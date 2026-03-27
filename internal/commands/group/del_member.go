package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// GroupDelMember removes a user from a group.
func GroupDelMember(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelMember", flag.ContinueOnError)
	var groupName, username string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&username, "user", "", "Username to remove")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelMember --group <groupName> --user <username>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelMember", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to remove members from this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.",groupName)}}},
		})
		return err
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User \"" + username + "\" not found. Check spelling or run accountList."}}},
		})
		return err
	}

	if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).Delete(&models.UserGroup{}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to remove member from group."}}},
		})
		return err
	}
	currentUser.InvalidateGroupsCache()

	console.DisplayBlock(console.ContentBlock{
		Title:     "Remove Member",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' removed from group '%s'.", username, groupName)}}},
	})
	return nil
}
