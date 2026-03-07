package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// GroupListAliases lists all aliases for a group.
func GroupListAliases(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListAliases", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListAliases --group <group_name>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListAliases", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list aliases for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	var aliases []models.Aliases
	if err := db.Where("group_id = ?", group.ID).Find(&aliases).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching aliases."}}},
		})
		return err
	}

	if len(aliases) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Aliases", Body: []string{"No aliases found for this group."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tAlias\tHostname\tAdded At")
	for _, alias := range aliases {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			alias.ID.String(),
			alias.ResolveFrom,
			alias.Host,
			alias.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Group Aliases",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Aliases", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}
