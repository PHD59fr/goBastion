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

// GroupListEgressKeys lists all egress SSH keys for a group.
func GroupListEgressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListEgressKeys", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListEgressKeys --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListEgressKeys", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list egress keys for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.",groupName)}}},
		})
		return err
	}

	var keys []models.GroupEgressKey
	if err := db.Where("group_id = ?", group.ID).Find(&keys).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Error fetching egress keys."}}},
		})
		return err
	}

	if len(keys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Keys", Body: []string{fmt.Sprintf("No egress keys found for group '%s'.", groupName)}}},
		})
		return nil
	}

	var sections []console.SectionContent
	for _, key := range keys {
		section := console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Created At: %s", key.CreatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.PubKey),
			},
		}
		sections = append(sections, section)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Egress Keys",
		BlockType: "success",
		Sections:  sections,
	})
	return nil
}
