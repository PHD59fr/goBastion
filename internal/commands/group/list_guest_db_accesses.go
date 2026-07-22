package group

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListGuestDBAccesses lists guest database access grants for a user in a group.
func ListGuestDBAccesses(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListGuestDBAccesses", flag.ContinueOnError)
	var groupName, account string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&account, "account", "", "Username to list guest DB accesses for")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(account) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest DB Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListGuestDBAccesses --group <group> --account <user>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListGuestDBAccesses", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest DB Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list guest DB accesses for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest DB Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found.", groupName)}}},
		})
		return err
	}

	var targetUser models.User
	if err := db.Where("username = ?", account).First(&targetUser).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest DB Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", account)}}},
		})
		return err
	}

	var grants []models.GroupGuestDBAccess
	if err := db.Preload("DatabaseHost").Where("group_id = ? AND user_id = ? AND deleted_at IS NULL", group.ID, targetUser.ID).Find(&grants).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest DB Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching guest DB accesses."}}},
		})
		return err
	}

	if len(grants) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest DB Accesses",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Guest DB Access", Body: []string{fmt.Sprintf("No guest DB access grants found for '%s' in group '%s'.", account, groupName)}}},
		})
		return nil
	}

	var bodyLines []string
	now := time.Now()
	for _, g := range grants {
		expires := "Never"
		if g.ExpiresAt != nil {
			if g.ExpiresAt.Before(now) {
				expires = "EXPIRED(" + g.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expires = g.ExpiresAt.Format("2006-01-02")
			}
		}
		dbName := g.Database
		if dbName == "" {
			dbName = "*"
		}
		allowedFrom := g.AllowedFrom
		if allowedFrom == "" {
			allowedFrom = "*"
		}
		line := fmt.Sprintf("  %s  %s  host=%s  proto=%s  db=%s  from=%s  expires=%s",
			g.ID.String()[:8], g.DatabaseHost.Name,
			g.DatabaseHost.Host, g.DatabaseHost.Protocol,
			dbName, allowedFrom, expires)
		if g.Comment != "" {
			line += "  (" + g.Comment + ")"
		}
		bodyLines = append(bodyLines, line)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Guest DB Accesses",
		BlockType: "success",
		Sections: []console.SectionContent{{
			SubTitle: fmt.Sprintf("Guest DB accesses for '%s' in group '%s'", account, groupName),
			Body:     bodyLines,
		}},
	})
	return nil
}
