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

// ListDBAliases lists all database aliases for a group.
func ListDBAliases(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListDBAliases", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListDBAliases --group <group_name>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListDBAliases", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: models.DescribeVisibilityDenial(models.VisibilityDeniedGroupPolicy, groupName, "")}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
		})
		return err
	}

	var aliases []models.DatabaseAlias
	if err := db.Where("group_id = ?", group.ID).Find(&aliases).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching aliases."}}},
		})
		return err
	}

	if len(aliases) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Aliases",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Aliases", Body: []string{"No aliases found for this group."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tAlias\tHost\tPort\tProtocol\tAdded At")
	for _, alias := range aliases {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			alias.ID.String(),
			alias.ResolveFrom,
			alias.Host,
			fmt.Sprintf("%d", alias.Port),
			alias.Protocol,
			alias.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Group DB Aliases",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Aliases", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}
