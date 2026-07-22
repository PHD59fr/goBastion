package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListDBAccesses lists all database accesses for a group.
func ListDBAccesses(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListDBAccesses", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListDBAccesses --group <group>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListDBAccesses", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list DB accesses for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
		})
		return err
	}

	var accesses []models.GroupDBAccess
	if err := db.Where("group_id = ?", group.ID).Find(&accesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching group DB accesses."}}},
		})
		return err
	}

	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group DB Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Access", Body: []string{"No DB accesses found for this group."}}},
		})
		return nil
	}

	rows := make([]utils.DBAccessRow, len(accesses))
	for i, a := range accesses {
		rows[i] = utils.GroupDBAccessToRow(a)
	}
	bodyLines := utils.RenderDBAccessTable(rows)

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Group DB Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "DB Accesses", Body: bodyLines}},
	})
	return nil
}
