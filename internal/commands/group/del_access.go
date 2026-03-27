package group

import (
	"bytes"
	"flag"
	"fmt"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GroupDelAccess removes an SSH access entry from a group.
func GroupDelAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelAccess", flag.ContinueOnError)
	var groupName, accessIDStr string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&accessIDStr, "access", "", "Access ID to remove")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || accessIDStr == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelAccess --group <groupName> --access <access_id>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete access for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.",groupName)}}},
		})
		return err
	}

	accessID, err := uuid.Parse(accessIDStr)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid ID", Body: []string{"Invalid access ID format."}}},
		})
		return err
	}

	if err := db.Where("id = ? AND group_id = ?", accessID, group.ID).Delete(&models.GroupAccess{}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error deleting group access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Group Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group access removed for group '%s'.", groupName)}}},
	})
	return nil
}
