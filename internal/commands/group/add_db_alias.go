package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddDBAlias creates a database alias for a group.
func AddDBAlias(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddDBAlias", flag.ContinueOnError)
	var groupName, alias, host, protocol string
	var port int
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&alias, "alias", "", "Alias")
	fs.StringVar(&host, "host", "", "Host")
	fs.IntVar(&port, "port", 0, "Port")
	fs.StringVar(&protocol, "protocol", "", "Protocol")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(alias) == "" || strings.TrimSpace(host) == "" || port == 0 || strings.TrimSpace(protocol) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddDBAlias --group <group_name> --alias <alias> --host <host> --port <port> --protocol <protocol>"}}},
		})
		if err != nil {
			return err
		}
		return fmt.Errorf("missing required arguments")
	}

	if !currentUser.CanDo(db, "groupAddDBAlias", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add aliases for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
		})
		return err
	}

	if !validation.IsValidDBProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol contains invalid characters."}}},
		})
		return fmt.Errorf("invalid protocol: %s", protocol)
	}
	var existing models.DatabaseAlias
	if err := db.Where("LOWER(resolve_from) = ? AND group_id = ? AND deleted_at IS NULL", strings.ToLower(alias), group.ID).First(&existing).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Duplicate", Body: []string{"An alias with this name already exists for this group."}}},
		})
		return fmt.Errorf("group DB alias %q already exists in group %q", alias, groupName)
	}

	newAlias := models.DatabaseAlias{
		ResolveFrom: alias,
		Host:        host,
		Port:        int64(port),
		Protocol:    protocol,
		GroupID:     &group.ID,
		UserID:      nil,
	}

	if err := db.Create(&newAlias).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error adding alias."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Group DB Alias",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Alias added successfully."}}},
	})
	return nil
}
