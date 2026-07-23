package self

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddDBAccess adds a personal database access entry for the current user.
func AddDBAccess(db *gorm.DB, user *models.User, args []string) error {

	fs := flag.NewFlagSet("selfAddDBAccess", flag.ContinueOnError)
	var host, username, comment, allowedFrom, protocol, password, database string
	var port int64
	var ttlDays int
	fs.StringVar(&host, "host", "", "Database host")
	fs.Int64Var(&port, "port", 0, "Port number")
	fs.StringVar(&protocol, "protocol", "", "Protocol: mysql, postgres, redis")
	fs.StringVar(&username, "user", "", "Database username")
	fs.StringVar(&password, "password", "", "Database password (encrypted if EGRESS_ENC_KEY is configured)")
	fs.StringVar(&database, "database", "", "Specific database name (optional)")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated, e.g. 10.0.0.0/8,192.168.1.0/24)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never, must be positive if set)")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Usage: selfAddDBAccess --host <host> --user <username> --protocol <mysql|postgres|redis> [--port <port>] [--password <password>] [--database <database>] [--comment <comment>] [--from <CIDRs>] [--ttl <days>]"}},
			},
		})
		return err
	}
	if strings.TrimSpace(host) == "" || strings.TrimSpace(username) == "" || strings.TrimSpace(protocol) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddDBAccess --host <host> --user <username> --protocol <mysql|postgres|redis> [--port <port>] [--password <password>] [--database <database>] [--comment <comment>] [--from <CIDRs>] [--ttl <days>]"}},
			},
		})
		return fmt.Errorf("missing required arguments")
	}
	if !validation.IsValidDBProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: mysql, postgres, redis"}}},
		})
		return fmt.Errorf("invalid protocol: %s", protocol)
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
	// Validate host
	if !validation.IsValidHost(host) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Host", Body: []string{"Host hostname/IP contains invalid characters (e.g., '@')."}}},
		})
		return fmt.Errorf("invalid host: %s", host)
	}
	// Apply default port from protocol if not specified
	if port == 0 {
		port = validation.DBProtocolDefaultPort(protocol)
	}
	// Validate port range
	if !validation.IsValidPort(port) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Port", Body: []string{"Port must be between 1 and 65535"}}},
		})
		return fmt.Errorf("invalid port: %d", port)
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

	// Encrypt password if provided
	var encryptedPassword string
	if password != "" {
		enc, err := cryptokey.ReEncryptIfNeeded(password)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Add Personal DB Access",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Encryption Error", Body: []string{fmt.Sprintf("Failed to process password: %s", err)}}},
			})
			return err
		}
		encryptedPassword = enc
	}

	var existingAccess models.SelfDBAccess
	result := db.Where("user_id = ? AND host = ? AND port = ? AND protocol = ?", user.ID, host, port, protocol).First(&existingAccess)
	if result.Error == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Access already exists for this host, port, and protocol."}},
			},
		})
		return fmt.Errorf("personal DB access already exists for %s:%d/%s", host, port, protocol)
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
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
		UserID:      user.ID,
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
