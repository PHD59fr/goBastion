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

// GroupList displays all groups, optionally filtered by membership.
func GroupList(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("groupList", flag.ContinueOnError)
	all := fs.Bool("all", false, "List all groups")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: groupList [--all]"}}},
		})
		return err
	}

	if !user.CanDo(db, "groupList", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list groups."}}},
		})
		return fmt.Errorf("access denied for %s", user.Username)
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "#\tID\tName")

	if *all {
		var groups []models.Group
		db.Unscoped().Find(&groups)
		if len(groups) == 0 {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Group List",
				BlockType: "info",
				Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"No groups found."}}},
			})
			return nil
		}
		for i, g := range groups {
			_, _ = fmt.Fprintf(w, "%d\t%s\t%s\n", i+1, g.ID.String(), g.Name)
		}
	} else {
		var userGroups []models.UserGroup
		if err := db.Preload("Group").Where("user_id = ?", user.ID).Find(&userGroups).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Group List",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to load your groups."}}},
			})
			return err
		}
		if len(userGroups) == 0 {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Group List",
				BlockType: "info",
				Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"You are not part of any groups."}}},
			})
			return nil
		}
		for i, ug := range userGroups {
			_, _ = fmt.Fprintf(w, "%d\t%s\t%s\n", i+1, ug.Group.ID.String(), ug.Group.Name)
		}
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "Group List",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Groups", Body: strings.Split(strings.TrimSpace(buf.String()), "\n")}},
	})
	return nil
}
