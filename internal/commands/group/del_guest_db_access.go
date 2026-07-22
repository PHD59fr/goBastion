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

// DelGuestDBAccess removes a guest database access grant from a group.
func DelGuestDBAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelGuestDBAccess", flag.ContinueOnError)
	var groupName, account, grantIDStr string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&account, "account", "", "Username whose guest DB access to remove")
	fs.StringVar(&grantIDStr, "grant", "", "Grant ID to remove (from groupListGuestDBAccesses)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || account == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelGuestDBAccess --group <group> --account <user> [--grant <grant_id>]"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelGuestDBAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to manage guest DB accesses for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found.", groupName)}}},
		})
		return err
	}

	var targetUser models.User
	if err := db.Where("username = ?", account).First(&targetUser).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", account)}}},
		})
		return err
	}

	query := db.Where("group_id = ? AND user_id = ? AND deleted_at IS NULL", group.ID, targetUser.ID)

	// If a specific grant ID is provided, delete only that one.
	if strings.TrimSpace(grantIDStr) != "" {
		grantID, err := uuid.Parse(grantIDStr)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Guest DB Access",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid ID", Body: []string{"Invalid grant ID format."}}},
			})
			return err
		}
		query = query.Where("id = ?", grantID)
	}

	result := query.Delete(&models.GroupGuestDBAccess{})
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error deleting guest DB access."}}},
		})
		return result.Error
	}
	if result.RowsAffected == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"No matching guest DB access grant found."}}},
		})
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Guest DB Access",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("Removed %d guest DB access grant(s) for '%s' in group '%s'.", result.RowsAffected, account, groupName),
		}}},
	})
	return nil
}
