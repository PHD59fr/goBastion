package self

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// isValidHost validates that the host string is a valid hostname or IP address without any disallowed characters.
func isValidHost(h string) bool {
	if strings.ContainsAny(h, " @/\\") {
		return false
	}
	host := h
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if net.ParseIP(host) != nil {
		return true
	}
	re := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	return re.MatchString(host)
}

// SelfAddAccess adds a personal SSH access entry for the current user.
func SelfAddAccess(db *gorm.DB, user *models.User, args []string) error {

	fs := flag.NewFlagSet("selfAddAccess", flag.ContinueOnError)
	var server, username, comment, allowedFrom, protocol string
	var port int64
	var ttlDays int
	var force bool
	fs.StringVar(&server, "server", "", "Server name")
	fs.StringVar(&username, "username", "", "SSH username")
	fs.Int64Var(&port, "port", 22, "Port number")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated, e.g. 10.0.0.0/8,192.168.1.0/24)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	fs.StringVar(&protocol, "protocol", "ssh", "Protocol restriction: ssh (all), scpupload, scpdownload, sftp, rsync")
	fs.BoolVar(&force, "force", false, "Skip TCP connectivity check")
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
				{SubTitle: "Usage", Body: []string{"selfAddAccess --server <server> --username <username> --port <port> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync] [--force]"}},
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
	// Validate server host
	if !isValidHost(server) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Server", Body: []string{"Server hostname/IP contains invalid characters (e.g., '@')."}}},
		})
		return nil
	}

	// Check TCP connectivity to server:port with 5s timeout (skip if --force)
	if !force {
		addr := net.JoinHostPort(server, strconv.FormatInt(port, 10))
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Add Personal Access",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Unreachable", Body: []string{fmt.Sprintf("Unable to connect to %s: %v", addr, err)}}},
			})
			return nil
		}
		_ = conn.Close()
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
