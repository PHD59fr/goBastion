package group

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"strconv"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// GroupAddAccess adds an SSH access entry to a group.
func GroupAddAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddAccess", flag.ContinueOnError)
	var groupName, server, username, comment, allowedFrom, protocol string
	var port int64
	var ttlDays int
	var force bool
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&server, "server", "", "Server to add access for")
	fs.Int64Var(&port, "port", 22, "Port number")
	fs.StringVar(&username, "username", "", "Connection username")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	fs.StringVar(&protocol, "protocol", "ssh", "Protocol restriction: ssh (all), scpupload, scpdownload, sftp, rsync")
	fs.BoolVar(&force, "force", false, "Skip TCP connectivity check")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || server == "" || username == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddAccess --group <groupName> --server <server> --port <port> --username <username> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync] [--force]"}}},
		})
		return nil
	}

	if !validation.IsValidHost(server) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Server", Body: []string{"Server hostname/IP contains invalid characters (e.g., '@')."}}},
		})
		return nil
	}

	// Check TCP connectivity to server:port with 5s timeout (skip if --force).
	// A failed connectivity check is a warning only — it must not block access creation.
	// Network reachability can change after the access entry is saved.
	if !force {
		addr := net.JoinHostPort(server, strconv.FormatInt(port, 10))
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Add Group Access",
				BlockType: "warning",
				Sections: []console.SectionContent{{
					SubTitle: "Connectivity Warning",
					Body: []string{
						fmt.Sprintf("Could not reach %s over TCP: %v", addr, err),
						"The access entry was saved anyway. Verify the target is reachable before connecting.",
						"Use --force to suppress this check.",
					},
				}},
			})
		} else {
			_ = conn.Close()
		}
	}

	if !currentUser.CanDo(db, "groupAddAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add access for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	if !validation.IsValidProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: ssh, scpupload, scpdownload, sftp, rsync"}}},
		})
		return nil
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.",groupName)}}},
		})
		return err
	}

	var existingAccess models.GroupAccess
	if err := db.Where("group_id = ? AND server = ? AND port = ? AND username = ?", group.ID, server, port, username).First(&existingAccess).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"Access already exists for this group with the given server, port, and username."}}},
		})
		return nil
	}

	access := models.GroupAccess{
		GroupID:     group.ID,
		Server:      server,
		Port:        port,
		Username:    username,
		Comment:     comment,
		AllowedFrom: allowedFrom,
		Protocol:    protocol,
	}
	if ttlDays > 0 {
		t := time.Now().AddDate(0, 0, ttlDays)
		access.ExpiresAt = &t
	}
	if err := db.Create(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to create group access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Group Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group access added for group '%s'.", groupName)}}},
	})
	return nil
}
