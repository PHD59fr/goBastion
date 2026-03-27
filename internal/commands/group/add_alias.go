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

// GroupAddAlias creates an alias for a group access target.
func GroupAddAlias(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddAlias", flag.ContinueOnError)
	var groupName, alias, hostname string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&alias, "alias", "", "Alias")
	fs.StringVar(&hostname, "hostname", "", "Host name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(alias) == "" || strings.TrimSpace(hostname) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddAlias --group <group_name> --alias <alias> --hostname <host_name>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupAddAlias", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add aliases for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.",groupName)}}},
		})
		return err
	}

	newHost := models.Aliases{
		ResolveFrom: alias,
		Host:        hostname,
		GroupID:     &group.ID,
		UserID:      nil,
	}

	if err := db.Create(&newHost).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error adding alias."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Group Alias",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Alias added successfully."}}},
	})
	return nil
}
