package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AccountAddAccess adds a personal SSH access entry for a user.
func AccountAddAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountAddAccess", flag.ContinueOnError)
	var targetUser, server, username, comment, allowedFrom, protocol string
	var port int64
	var ttlDays int
	fs.StringVar(&targetUser, "user", "", "Target username")
	fs.StringVar(&server, "server", "", "SSH Server")
	fs.StringVar(&username, "username", "", "SSH Username")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.Int64Var(&port, "port", 22, "SSH Port")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	fs.StringVar(&protocol, "protocol", "ssh", "Protocol restriction: ssh (all), scpupload, scpdownload, sftp, rsync")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountAddAccess --user <username> --server <host> --username <user> --port <port> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync]"}}},
		})
		return err
	}

	if strings.TrimSpace(targetUser) == "" || strings.TrimSpace(server) == "" || strings.TrimSpace(username) == "" || port <= 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountAddAccess --user <username> --server <host> --username <user> --port <port> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync]"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountAddAccess", targetUser) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add personal access for this user."}}},
		})
		return nil
	}

	if !validation.IsValidProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: ssh, scpupload, scpdownload, sftp, rsync"}}},
		})
		return nil
	}
	if !validation.IsValidPort(port) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Port", Body: []string{"Port must be between 1 and 65535"}}},
		})
		return nil
	}
	if !validation.IsValidCIDRs(allowedFrom) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid CIDRs", Body: []string{"--from must be a comma-separated list of valid CIDR notation (e.g. 10.0.0.0/8,192.168.1.0/24)"}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", targetUser).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", targetUser)}}},
		})
		return err
	}

	access := models.SelfAccess{UserID: user.ID, Server: server, Username: username, Port: port, Comment: comment, AllowedFrom: allowedFrom, Protocol: protocol}
	if ttlDays > 0 {
		t := time.Now().AddDate(0, 0, ttlDays)
		access.ExpiresAt = &t
	}
	if err := db.Create(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to create personal access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Personal access added successfully."}}},
	})

	return nil
}
