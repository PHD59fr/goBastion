package group

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

var groupNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Create creates a new group.
func Create(db *gorm.DB, currentUser *models.User, args []string) error {
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

	if len(groupName) > 64 || !groupNameRegexp.MatchString(groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Name", Body: []string{"Group name must be alphanumeric (start with letter/digit), max 64 characters. Allowed: letters, digits, '.', '_', '-'."}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "groupCreate", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to create groups."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	// Group creation is administrator-only. Lock the same administrator set
	// across creators, including on MariaDB without partial unique indexes.
	if err := models.WithAccountChange(db, func(tx *gorm.DB) error {
		var actor models.User
		if err := tx.Where(map[string]any{"id": currentUser.ID, "enabled": true, "system_user": false, "role": models.RoleAdmin}).First(&actor).Error; err != nil {
			return fmt.Errorf("administrator access is no longer valid: %w", err)
		}
		var existing models.Group
		if err := tx.Where("name = ?", groupName).First(&existing).Error; err == nil {
			return fmt.Errorf("group '%s' already exists", groupName)
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		return tx.Create(&models.Group{Name: groupName}).Error
	}); err != nil {
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
