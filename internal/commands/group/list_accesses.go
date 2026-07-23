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

// ListAccesses lists all SSH accesses for a group.
func ListAccesses(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListAccesses", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListAccesses --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListAccesses", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: models.DescribeVisibilityDenial(models.VisibilityDeniedGroupPolicy, groupName, "")}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
		})
		return err
	}

	var accesses []models.GroupAccess
	if err := db.Where("group_id = ?", group.ID).Find(&accesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching group accesses."}}},
		})
		return err
	}

	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Access", Body: []string{"No accesses found for this group."}}},
		})
		return nil
	}

	rows := make([]utils.AccessRow, len(accesses))
	for i, a := range accesses {
		rows[i] = utils.GroupAccessToRow(a)
	}
	bodyLines := utils.RenderAccessTable(rows)

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Group Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Accesses", Body: bodyLines}},
	})
	return nil
}
