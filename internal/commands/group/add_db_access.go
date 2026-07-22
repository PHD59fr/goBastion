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

// AddDBAccess adds a database access entry to a group.
func AddDBAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddDBAccess", flag.ContinueOnError)
	var groupName, host, database, comment, allowedFrom string
	var ttlDays int
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&host, "host", "", "DatabaseHost name")
	fs.StringVar(&database, "database", "", "Specific database name (optional)")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never, must be positive if set)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || host == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddDBAccess --group <group> --host <host> [--database <database>] [--comment <comment>] [--from <CIDRs>] [--ttl <days>]"}}},
		})
		return fmt.Errorf("missing required arguments")
	}

	if !currentUser.CanDo(db, "groupAddDBAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add DB access for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	// Validate CIDRs
	if !validation.IsValidCIDRs(allowedFrom) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid CIDRs", Body: []string{"--from must be a comma-separated list of valid CIDR notation (e.g. 10.0.0.0/8,192.168.1.0/24)"}}},
		})
		return fmt.Errorf("invalid CIDRs: %s", allowedFrom)
	}
	// Validate TTL - must be zero (never) or positive
	if ttlDays < 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid TTL", Body: []string{"TTL must be zero (never) or a positive number of days"}}},
		})
		return fmt.Errorf("invalid TTL: %d", ttlDays)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
		})
		return err
	}

	// Look up the DatabaseHost by name.
	var dbHost models.DatabaseHost
	if err := db.Where("name = ?", host).First(&dbHost).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("DatabaseHost '%s' not found. Check spelling.", host)}}},
		})
		return err
	}

	// Check for duplicate.
	var existingAccess models.GroupDBAccess
	if err := db.Where("group_id = ? AND database_host_id = ? AND deleted_at IS NULL", group.ID, dbHost.ID).First(&existingAccess).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"Access already exists for this group with the given database host."}}},
		})
		return nil
	}

	access := models.GroupDBAccess{
		GroupID:        group.ID,
		DatabaseHostID: dbHost.ID,
		Database:       database,
		Comment:        comment,
		AllowedFrom:    allowedFrom,
	}
	if ttlDays > 0 {
		t := time.Now().AddDate(0, 0, ttlDays)
		access.ExpiresAt = &t
	}
	if err := db.Create(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to create group DB access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Group DB Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group DB access added for group '%s'.", groupName)}}},
	})
	return nil
}
