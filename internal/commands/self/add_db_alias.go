package self

import (
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddDBAlias creates a personal database alias.
func AddDBAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddDBAlias", flag.ContinueOnError)
	var alias, host, protocol string
	var port int
	fs.StringVar(&alias, "alias", "", "Alias")
	fs.StringVar(&host, "host", "", "Host")
	fs.IntVar(&port, "port", 0, "Port")
	fs.StringVar(&protocol, "protocol", "", "Protocol")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfAddDBAlias --alias <alias> --host <host> --port <port> --protocol <protocol>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(alias) == "" || strings.TrimSpace(host) == "" || port == 0 || strings.TrimSpace(protocol) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddDBAlias --alias <alias> --host <host> --port <port> --protocol <protocol>"}},
			},
		})
		return fmt.Errorf("missing required arguments")
	}
	if !validation.IsValidDBProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Invalid Protocol", Body: []string{"Protocol contains invalid characters."}},
			},
		})
		return fmt.Errorf("invalid protocol: %s", protocol)
	}
	var existing models.DatabaseAlias
	if err := db.Where("LOWER(resolve_from) = ? AND user_id = ? AND deleted_at IS NULL", strings.ToLower(alias), user.ID).First(&existing).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Duplicate", Body: []string{"An alias with this name already exists."}},
			},
		})
		return fmt.Errorf("personal DB alias %q already exists", alias)
	}
	newAlias := models.DatabaseAlias{
		ResolveFrom: alias,
		Host:        host,
		Port:        int64(port),
		Protocol:    protocol,
		UserID:      &user.ID,
	}
	if err := db.Create(&newAlias).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add alias. Please contact admin."}},
			},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal DB Alias",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Alias added successfully."}},
		},
	})
	return nil
}
