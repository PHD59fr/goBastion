package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// GroupListAccesses lists all SSH accesses for a group.
func GroupListAccesses(db *gorm.DB, currentUser *models.User, args []string) error {
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
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list accesses for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.",groupName)}}},
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

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tUsername\tServer\tPort\tProtocol\tComment\tFrom\tExpires\tLast Used\tCreated At")
	for _, access := range accesses {
		lastUsed := "Never"
		if !access.LastConnection.IsZero() {
			lastUsed = access.LastConnection.Format("2006-01-02 15:04:05")
		}
		expiresStr := "Never"
		if access.ExpiresAt != nil {
			if access.ExpiresAt.Before(time.Now()) {
				expiresStr = "EXPIRED(" + access.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expiresStr = access.ExpiresAt.Format("2006-01-02")
			}
		}
		fromStr := access.AllowedFrom
		if fromStr == "" {
			fromStr = "*"
		}
		proto := access.Protocol
		if proto == "" {
			proto = "ssh"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			access.ID.String(),
			access.Username,
			access.Server,
			access.Port,
			proto,
			access.Comment,
			fromStr,
			expiresStr,
			lastUsed,
			access.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Group Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Accesses", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}
