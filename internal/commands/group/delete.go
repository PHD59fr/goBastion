package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Delete removes a group and its associated data.
func Delete(db *gorm.DB, currentUser *models.User, args []string) error {
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
		if err != nil {
			return err
		}
		return fmt.Errorf("invalid or missing arguments")
	}

	if !currentUser.CanDo(db, "groupDelete", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete groups."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	err := db.Transaction(func(tx *gorm.DB) error {
		var group models.Group
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("name = ?", groupName).First(&group).Error; err != nil {
			return err
		}
		// Soft-delete the complete grant set in the same transaction. No old
		// membership, credential or alias can survive the group's removal.
		for _, row := range []any{
			&models.UserGroup{}, &models.GroupAccess{}, &models.GroupGuestAccess{},
			&models.GroupDBAccess{}, &models.GroupGuestDBAccess{}, &models.GroupEgressKey{},
			&models.Aliases{}, &models.DatabaseAlias{},
		} {
			if err := tx.Where("group_id = ?", group.ID).Delete(row).Error; err != nil {
				return err
			}
		}
		return tx.Delete(&group).Error
	})
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{fmt.Sprintf("Failed to delete group '%s'.", groupName)}}},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Delete",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group '%s' deleted successfully.", groupName)}}},
	})
	return nil
}
