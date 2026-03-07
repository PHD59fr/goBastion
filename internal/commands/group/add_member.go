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

// GroupAddMember adds a user to a group with a specified role.
func GroupAddMember(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddMember", flag.ContinueOnError)
	var groupName, username, role string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&username, "user", "", "Username to add")
	fs.StringVar(&role, "role", "", "Role (owner, aclkeeper, gatekeeper, member, guest)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(username) == "" || strings.TrimSpace(role) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddMember --group <groupName> --user <username> --role <role>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupAddMember", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add members to this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group not found: %s", groupName)}}},
		})
		return err
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User not found: %s", username)}}},
		})
		return err
	}

	var existingUG models.UserGroup
	if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).First(&existingUG).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Already Exists", Body: []string{fmt.Sprintf("User '%s' is already in group '%s'.", username, groupName)}}},
		})
		return nil
	}

	newUG := models.UserGroup{UserID: u.ID, GroupID: g.ID, Role: role}
	if err := db.Create(&newUG).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to add member to group."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Member",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' added to group '%s' as '%s'.", username, groupName, role)}}},
	})
	return nil
}
