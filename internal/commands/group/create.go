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

// GroupCreate creates a new group.
func GroupCreate(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupCreate", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupCreate --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupCreate", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to create groups."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var existingGroup models.Group
	if err := db.Unscoped().Where("name = ? AND deleted_at IS NULL", groupName).First(&existingGroup).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Exists", Body: []string{fmt.Sprintf("Group '%s' already exists.", groupName)}}},
		})
		return nil
	}

	g := models.Group{Name: groupName}
	if err := db.Create(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Error creating group."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Create",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group '%s' created successfully.", groupName)}}},
	})
	return nil
}
