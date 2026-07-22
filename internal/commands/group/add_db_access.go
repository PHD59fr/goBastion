package group

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddDBAccess adds a database access entry to a group.
func AddDBAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddDBAccess", flag.ContinueOnError)
	var groupName, host, username, comment, allowedFrom, protocol, password, database string
	var port int64
	var ttlDays int
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&host, "host", "", "Database host")
	fs.Int64Var(&port, "port", 0, "Port number")
	fs.StringVar(&protocol, "protocol", "", "Protocol: mysql, postgres, redis")
	fs.StringVar(&username, "user", "", "Database username")
	fs.StringVar(&password, "password", "", "Database password (encrypted if EGRESS_ENC_KEY is configured)")
	fs.StringVar(&database, "database", "", "Specific database name (optional)")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never, must be positive if set)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || host == "" || username == "" || protocol == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddDBAccess --group <group> --host <host> --user <username> --protocol <mysql|postgres|redis> [--port <port>] [--password <password>] [--database <database>] [--comment <comment>] [--from <CIDRs>] [--ttl <days>]"}}},
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

	if !validation.IsValidDBProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: mysql, postgres, redis"}}},
		})
		return fmt.Errorf("invalid protocol: %s", protocol)
	}
	if !validation.IsValidHost(host) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Host", Body: []string{"Host hostname/IP contains invalid characters (e.g., '@')."}}},
		})
		return fmt.Errorf("invalid host: %s", host)
	}
	// Apply default port from protocol if not specified
	if port == 0 {
		port = validation.DBProtocolDefaultPort(protocol)
	}
	if !validation.IsValidPort(port) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Port", Body: []string{"Port must be between 1 and 65535"}}},
		})
		return fmt.Errorf("invalid port: %d", port)
	}
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

	// Encrypt password if provided
	var encryptedPassword string
	if password != "" {
		enc, err := cryptokey.ReEncryptIfNeeded(password)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Add Group DB Access",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Encryption Error", Body: []string{fmt.Sprintf("Failed to process password: %s", err)}}},
			})
			return err
		}
		encryptedPassword = enc
	}

	// Check for duplicate.
	var existingAccess models.GroupDBAccess
	if err := db.Where("group_id = ? AND host = ? AND port = ? AND protocol = ?", group.ID, host, port, protocol).First(&existingAccess).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"Access already exists for this group with the given host, port, and protocol."}}},
		})
		return nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Database error while checking for existing access. Please try again."}}},
		})
		return fmt.Errorf("database error: %v", err)
	}

	access := models.GroupDBAccess{
		GroupID:     group.ID,
		Host:        host,
		Port:        port,
		Protocol:    protocol,
		Username:    username,
		Password:    encryptedPassword,
		Database:    database,
		Comment:     comment,
		AllowedFrom: allowedFrom,
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
