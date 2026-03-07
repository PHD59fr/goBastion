package self

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// SelfListAliases lists all personal aliases for the current user.
func SelfListAliases(db *gorm.DB, user *models.User) error {
	var hosts []models.Aliases
	result := db.Where("user_id = ?", user.ID).Find(&hosts)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Aliases",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving aliases. Please contact admin."}},
			},
		})
		return result.Error
	}
	if len(hosts) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Aliases",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "No Aliases Found", Body: []string{"You have not added any aliases."}},
			},
		})
		return nil
	}
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tAlias\tHostname\tAdded At")
	for _, host := range hosts {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			host.ID.String(),
			host.ResolveFrom,
			host.Host,
			host.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()
	tableOutput := buf.String()
	bodyLines := strings.Split(strings.TrimSpace(tableOutput), "\n")
	block := console.ContentBlock{
		Title:     "My Aliases",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Aliases", Body: bodyLines},
		},
	}
	console.DisplayBlock(block)
	return nil
}
