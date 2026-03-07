package self

import (
	"flag"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// SelfAddAlias creates an alias for a personal access target.
func SelfAddAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddAlias", flag.ContinueOnError)
	var alias, hostname string
	fs.StringVar(&alias, "alias", "", "Alias")
	fs.StringVar(&hostname, "hostname", "", "Host name")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfAddAlias --alias <alias> --hostname <host_name>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(alias) == "" || strings.TrimSpace(hostname) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddAlias --alias <alias> --hostname <host_name>"}},
			},
		})
		return nil
	}
	newHost := models.Aliases{
		ResolveFrom: alias,
		Host:        hostname,
		UserID:      &user.ID,
		GroupID:     nil,
	}
	if err := db.Create(&newHost).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add alias. Please contact admin."}},
			},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal Alias",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Alias added successfully."}},
		},
	})
	return nil
}
