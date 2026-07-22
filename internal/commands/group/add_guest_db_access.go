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

// AddGuestDBAccess grants a guest-role user database access within a group.
func AddGuestDBAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddGuestDBAccess", flag.ContinueOnError)
	var groupName, account, host, username, comment, allowedFrom, protocol, password, database string
	var port int64
	var ttlDays int
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&account, "account", "", "Username to grant guest DB access to")
	fs.StringVar(&host, "host", "", "Database host")
	fs.Int64Var(&port, "port", 0, "Port number")
	fs.StringVar(&protocol, "protocol", "", "Protocol: mysql, postgres, mongo, redis")
	fs.StringVar(&username, "user", "", "Database username")
	fs.StringVar(&password, "password", "", "Database password (will be encrypted)")
	fs.StringVar(&database, "database", "", "Specific database name (optional)")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || account == "" || host == "" || username == "" || protocol == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Usage", Body: []string{
				"Usage: groupAddGuestDBAccess --group <group> --account <user> --host <host> --user <username> --protocol <mysql|postgres|mongo|redis> [--port <port>] [--password <password>] [--database <database>] [--comment <text>] [--from <CIDRs>] [--ttl <days>]",
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

	if !validation.IsValidDBProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: mysql, postgres, mongo, redis"}}},
		})
		return fmt.Errorf("invalid protocol: %s", protocol)
	}
	if !validation.IsValidHost(host) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Host", Body: []string{"Host hostname/IP contains invalid characters."}}},
		})
		return fmt.Errorf("invalid host: %s", host)
	}
	// Apply default port from protocol if not specified
	if port == 0 {
		port = validation.DBProtocolDefaultPort(protocol)
	}
	if !validation.IsValidPort(port) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Port", Body: []string{"Port must be between 1 and 65535"}}},
		})
		return fmt.Errorf("invalid port: %d", port)
	}
	if !validation.IsValidCIDRs(allowedFrom) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid CIDRs", Body: []string{"--from must be a comma-separated list of valid CIDRs"}}},
		})
		return fmt.Errorf("invalid CIDRs: %s", allowedFrom)
	}
	if ttlDays < 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid TTL", Body: []string{"TTL must be zero (never) or positive"}}},
		})
		return fmt.Errorf("invalid TTL: %d", ttlDays)
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

	// Encrypt password if provided
	var encryptedPassword string
	if password != "" {
		enc, err := cryptokey.Encrypt(password)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Add Guest DB Access",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Encryption Error", Body: []string{fmt.Sprintf("Failed to encrypt password: %s", err)}}},
			})
			return err
		}
		encryptedPassword = enc
	}

	// Check for duplicate.
	var existing models.GroupGuestDBAccess
	if err := db.Where("group_id = ? AND user_id = ? AND host = ? AND port = ? AND protocol = ? AND deleted_at IS NULL",
		group.ID, targetUser.ID, host, port, protocol).First(&existing).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Already Exists", Body: []string{"This guest DB access grant already exists."}}},
		})
		return nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest DB Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Database error while checking for existing access. Please try again."}}},
		})
		return fmt.Errorf("database error: %v", err)
	}

	guestAccess := models.GroupGuestDBAccess{
		GroupID:     group.ID,
		UserID:      targetUser.ID,
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
			fmt.Sprintf("Guest DB access granted to '%s' for %s@%s:%d (%s) in group '%s'.", account, username, host, port, protocol, groupName),
			"Use groupListGuestDBAccesses to review.",
		}}},
	})
	return nil
}
