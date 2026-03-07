package self

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// SelfAddAccess adds a personal SSH access entry for the current user.
func SelfAddAccess(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddAccess", flag.ContinueOnError)
	var server, username, comment, allowedFrom, protocol string
	var port int64
	var ttlDays int
	fs.StringVar(&server, "server", "", "Server name")
	fs.StringVar(&username, "username", "", "SSH username")
	fs.Int64Var(&port, "port", 22, "Port number")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated, e.g. 10.0.0.0/8,192.168.1.0/24)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	fs.StringVar(&protocol, "protocol", "ssh", "Protocol restriction: ssh (all), scpupload, scpdownload, sftp, rsync")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Usage: selfAddAccess --server <server> --username <username> --port <port> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync]"}},
			},
		})
		return err
	}
	if strings.TrimSpace(server) == "" || strings.TrimSpace(username) == "" || port <= 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddAccess --server <server> --username <username> --port <port> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync]"}},
			},
		})
		return nil
	}
	validProtocols := map[string]bool{"ssh": true, "scpupload": true, "scpdownload": true, "sftp": true, "rsync": true}
	if !validProtocols[protocol] {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: ssh, scpupload, scpdownload, sftp, rsync"}}},
		})
		return nil
	}
	var existingAccess models.SelfAccess
	result := db.Where("user_id = ? AND server = ? AND username = ? AND port = ?", user.ID, server, username, port).First(&existingAccess)
	if result.Error == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Access already exists for this server with the given username and port."}},
			},
		})
		return nil
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred. Please contact admin."}},
			},
		})
		return fmt.Errorf("database error: %v", result.Error)
	}
	access := models.SelfAccess{
		UserID:      user.ID,
		Server:      server,
		Username:    username,
		Port:        port,
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
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add personal access. Please contact admin."}},
			},
		})
		return fmt.Errorf("error adding personal access: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal Access",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Personal access added successfully."}},
		},
	})
	return nil
}
