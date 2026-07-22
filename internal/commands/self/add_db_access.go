package self

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddDBAccess adds a personal database access entry for the current user.
func AddDBAccess(db *gorm.DB, user *models.User, args []string) error {

	fs := flag.NewFlagSet("selfAddDBAccess", flag.ContinueOnError)
	var host, database, comment, allowedFrom string
	var ttlDays int
	fs.StringVar(&host, "host", "", "DatabaseHost name")
	fs.StringVar(&database, "database", "", "Specific database name (optional)")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated, e.g. 10.0.0.0/8,192.168.1.0/24)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never, must be positive if set)")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Usage: selfAddDBAccess --host <host> [--database <database>] [--comment <comment>] [--from <CIDRs>] [--ttl <days>]"}},
			},
		})
		return err
	}
	if strings.TrimSpace(host) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddDBAccess --host <host> [--database <database>] [--comment <comment>] [--from <CIDRs>] [--ttl <days>]"}},
			},
		})
		return fmt.Errorf("missing required arguments")
	}
	// Validate TTL - must be zero (never) or positive
	if ttlDays < 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid TTL", Body: []string{"TTL must be zero (never) or a positive number of days"}}},
		})
		return fmt.Errorf("invalid TTL: %d", ttlDays)
	}
	// Validate CIDRs
	if !validation.IsValidCIDRs(allowedFrom) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid CIDRs", Body: []string{"--from must be a comma-separated list of valid CIDR notation (e.g. 10.0.0.0/8,192.168.1.0/24)"}}},
		})
		return fmt.Errorf("invalid CIDRs: %s", allowedFrom)
	}

	// Look up the DatabaseHost by name.
	var dbHost models.DatabaseHost
	if err := db.Where("name = ?", host).First(&dbHost).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Not Found", Body: []string{fmt.Sprintf("DatabaseHost '%s' not found. Check spelling.", host)}},
			},
		})
		return err
	}

	// Check for duplicate (same user_id + database_host_id).
	var existingAccess models.SelfDBAccess
	result := db.Where("user_id = ? AND database_host_id = ? AND deleted_at IS NULL", user.ID, dbHost.ID).First(&existingAccess)
	if result.Error == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Access already exists for this database host."}},
			},
		})
		return nil
	} else if !strings.Contains(result.Error.Error(), "record not found") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Database error while checking for existing access. Please try again."}},
			},
		})
		return fmt.Errorf("database error: %v", result.Error)
	}
	access := models.SelfDBAccess{
		UserID:         user.ID,
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
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add personal DB access. Please contact admin."}},
			},
		})
		return fmt.Errorf("error adding personal DB access: %w", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal DB Access",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Personal DB access added successfully."}},
		},
	})
	return nil
}
