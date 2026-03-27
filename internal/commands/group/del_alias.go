package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GroupDelAlias removes an alias from a group.
func GroupDelAlias(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelAlias", flag.ContinueOnError)
	var groupName, hostID string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&hostID, "id", "", "Alias ID")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(hostID) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelAlias --group <group_name> --id <alias_id>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelAlias", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete aliases for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.",groupName)}}},
		})
		return err
	}

	parsedID, err := uuid.Parse(hostID)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid ID", Body: []string{"Invalid alias ID format."}}},
		})
		return err
	}

	var host models.Aliases
	if err := db.Where("id = ? AND group_id = ?", parsedID, group.ID).First(&host).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"No alias found with the given ID for the current group."}}},
		})
		return err
	}

	if err := db.Delete(&host).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error deleting alias."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Group Alias",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Alias deleted successfully."}}},
	})
	return nil
}
