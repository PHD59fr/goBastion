package group

import (
	"bytes"
	"flag"
	"fmt"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddGuestDBAccess grants a guest-role user database access within a group.
func AddGuestDBAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddGuestDBAccess", flag.ContinueOnError)
	var groupName, account, host, database, comment, allowedFrom string
	var ttlDays int
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&account, "account", "", "Username to grant guest DB access to")
	fs.StringVar(&host, "host", "", "DatabaseHost name")
	fs.StringVar(&database, "database", "", "Specific database name (optional)")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || account == "" || host == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Usage", Body: []string{
				"Usage: groupAddGuestDBAccess --group <group> --account <user> --host <host> [--database <database>] [--comment <text>] [--from <CIDRs>] [--ttl <days>]",
			}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupAddGuestDBAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to manage guest DB accesses for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	if !validation.IsValidCIDRs(allowedFrom) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid CIDRs", Body: []string{"--from must be a comma-separated list of valid CIDRs"}}},
		})
		return nil
	}
	if ttlDays < 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid TTL", Body: []string{"TTL must be zero (never) or positive"}}},
		})
		return nil
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found.", groupName)}}},
		})
		return err
	}

	var targetUser models.User
	if err := db.Where("username = ?", account).First(&targetUser).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", account)}}},
		})
		return err
	}

	// Verify the target user is a guest in this group.
	var ug models.UserGroup
	if err := db.Where("user_id = ? AND group_id = ? AND deleted_at IS NULL", targetUser.ID, group.ID).First(&ug).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not a Member", Body: []string{fmt.Sprintf("User '%s' is not a member of group '%s'. Add them first with groupAddMember.", account, groupName)}}},
		})
		return err
	}
	if ug.Role != models.GroupRoleGuest {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Wrong Role", Body: []string{fmt.Sprintf("User '%s' has role '%s' in group '%s', not 'guest'. Guest access grants only apply to guest-role users.", account, ug.Role, groupName)}}},
		})
		return nil
	}

	// Look up the DatabaseHost by name.
	var dbHost models.DatabaseHost
	if err := db.Where("name = ?", host).First(&dbHost).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("DatabaseHost '%s' not found. Check spelling.", host)}}},
		})
		return err
	}

	// Check for duplicate.
	var existing models.GroupGuestDBAccess
	if err := db.Where("group_id = ? AND user_id = ? AND database_host_id = ? AND deleted_at IS NULL",
		group.ID, targetUser.ID, dbHost.ID).First(&existing).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Already Exists", Body: []string{"This guest DB access grant already exists."}}},
		})
		return nil
	}

	guestAccess := models.GroupGuestDBAccess{
		GroupID:        group.ID,
		UserID:         targetUser.ID,
		DatabaseHostID: dbHost.ID,
		Database:       database,
		Comment:        comment,
		AllowedFrom:    allowedFrom,
	}
	if ttlDays > 0 {
		t := time.Now().AddDate(0, 0, ttlDays)
		guestAccess.ExpiresAt = &t
	}

	if err := db.Create(&guestAccess).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to create guest DB access grant."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Guest DB Access",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("Guest DB access granted to '%s' for host '%s' in group '%s'.", account, host, groupName),
			"Use groupListGuestDBAccesses to review.",
		}}},
	})
	return nil
}
