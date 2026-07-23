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

// ListGuestAccesses lists guest access grants for a user in a group.
func ListGuestAccesses(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListGuestAccesses", flag.ContinueOnError)
	var groupName, account string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&account, "account", "", "Username to list guest accesses for")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(account) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListGuestAccesses --group <group> --account <user>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListGuestAccesses", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: models.DescribeVisibilityDenial(models.VisibilityDeniedGroupPolicy, groupName, "")}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}
	if !currentUser.CanInspectGuestGrantTarget(db, groupName, account) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: models.DescribeVisibilityDenial(models.VisibilityDeniedGuestOwnOnly, groupName, account)}},
		})
		return fmt.Errorf("access denied for %s on guest grants of %s in group %s", currentUser.Username, account, groupName)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found.", groupName)}}},
		})
		return err
	}

	var targetUser models.User
	if err := db.Where("username = ?", account).First(&targetUser).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", account)}}},
		})
		return err
	}

	var grants []models.GroupGuestAccess
	if err := db.Where("group_id = ? AND user_id = ? AND deleted_at IS NULL", group.ID, targetUser.ID).Find(&grants).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest Accesses",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching guest accesses."}}},
		})
		return err
	}

	if len(grants) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Guest Accesses",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Guest Access", Body: []string{fmt.Sprintf("No guest access grants found for '%s' in group '%s'.", account, groupName)}}},
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
		proto := g.Protocol
		if proto == "" {
			proto = "ssh"
		}
		allowedFrom := g.AllowedFrom
		if allowedFrom == "" {
			allowedFrom = "*"
		}
		line := fmt.Sprintf("  %s  %s@%s:%d  proto=%s  from=%s  expires=%s",
			g.ID.String()[:8], g.Username, g.Server, g.Port, proto, allowedFrom, expires)
		if g.Comment != "" {
			line += "  (" + g.Comment + ")"
		}
		bodyLines = append(bodyLines, line)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Guest Accesses",
		BlockType: "success",
		Sections: []console.SectionContent{{
			SubTitle: fmt.Sprintf("Guest accesses for '%s' in group '%s'", account, groupName),
			Body:     bodyLines,
		}},
	})
	return nil
}
