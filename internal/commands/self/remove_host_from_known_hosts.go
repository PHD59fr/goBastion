package self

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"log/slog"

	"goBastion/internal/osadapter"
	gosync "goBastion/internal/utils/sync"

	"gorm.io/gorm"
)

// SelfRemoveHostFromKnownHosts removes all known_hosts entries for a host from the DB and syncs to disk.
func SelfRemoveHostFromKnownHosts(db *gorm.DB, u *models.User, args []string) error {
	return removeHostFromKnownHosts(db, u, args, false)
}

// SelfReplaceKnownHost removes the stored key for a host so the new key is trusted on next connection.
func SelfReplaceKnownHost(db *gorm.DB, u *models.User, args []string) error {
	return removeHostFromKnownHosts(db, u, args, true)
}

// removeHostFromKnownHosts is the shared implementation for both removal commands.
func removeHostFromKnownHosts(db *gorm.DB, u *models.User, args []string, replace bool) error {
	title := "Remove Host from Known Hosts"
	if replace {
		title = "Replace Known Host Key"
	}

	fs := flag.NewFlagSet("knownHosts", flag.ContinueOnError)
	var hostname string
	fs.StringVar(&hostname, "host", "", "Hostname or IP")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(hostname) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     title,
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"Usage: --host <hostname_or_ip>"}},
			},
		})
		return fmt.Errorf("missing required flag --host")
	}

	// Match entries for this host (port 22: "hostname keytype key", other ports: "[hostname]:port keytype key")
	var entries []models.KnownHostsEntry
	if err := db.Where("user_id = ?", u.ID).Find(&entries).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     title,
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Database Error", Body: []string{"Failed to query known hosts entries."}},
			},
		})
		return err
	}

	var toDelete []string
	for _, e := range entries {
		parts := strings.Fields(e.Entry)
		if len(parts) < 1 {
			continue
		}
		host := parts[0]
		// Match "hostname" (port 22) or "[hostname]:..." (any port)
		if host == hostname || strings.HasPrefix(host, "["+hostname+"]:") {
			toDelete = append(toDelete, e.ID.String())
		}
	}

	if len(toDelete) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     title,
			BlockType: "warning",
			Sections: []console.SectionContent{
				{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Host '%s' was not found in known hosts.", hostname)}},
			},
		})
		return nil
	}

	if err := db.Where("id IN ?", toDelete).Delete(&models.KnownHostsEntry{}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     title,
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{fmt.Sprintf("Failed to delete entries: %v", err)}},
			},
		})
		return err
	}

	if err := gosync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).KnownHostsFromDB(u); err != nil {
		return fmt.Errorf("error syncing known_hosts: %w", err)
	}

	var successMsg string
	if replace {
		successMsg = fmt.Sprintf("Old key for '%s' removed. The new key will be trusted on your next connection.", hostname)
	} else {
		successMsg = fmt.Sprintf("Host '%s' successfully removed from known hosts.", hostname)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     title,
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{successMsg}},
		},
	})
	return nil
}
