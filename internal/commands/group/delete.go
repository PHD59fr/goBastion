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

// GroupDelete removes a group and its associated data.
func GroupDelete(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelete", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelete --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelete", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete groups."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	db.Where("name = ?", groupName).Delete(&models.Group{})
	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Delete",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group '%s' deleted successfully.", groupName)}}},
	})
	return nil
}
