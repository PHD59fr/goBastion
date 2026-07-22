package db

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListHosts displays all DatabaseHosts, optionally filtered by protocol.
func ListHosts(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("dbListHosts", flag.ContinueOnError)
	var protocol string
	fs.StringVar(&protocol, "protocol", "", "Filter by protocol (mysql, postgres, mongo, redis)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB List Hosts",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: dbListHosts [--protocol <protocol>]"}}},
		})
		return err
	}

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB List Hosts",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only administrators can list database hosts."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var hosts []models.DatabaseHost
	q := db.Unscoped().Where("deleted_at IS NULL")
	if strings.TrimSpace(protocol) != "" {
		q = q.Where("protocol = ?", protocol)
	}
	if err := q.Find(&hosts).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB List Hosts",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to list database hosts."}}},
		})
		return err
	}

	if len(hosts) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB List Hosts",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"No database hosts found."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "#\tID\tName\tHost\tPort\tProtocol\tUser\tHasPassword\tComment")
	for i, h := range hosts {
		hasPassword := "no"
		if h.Password != "" {
			hasPassword = "yes"
		}
		shortID := h.ID.String()[:8]
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			i+1, shortID, h.Name, h.Host, h.Port, h.Protocol, h.Username, hasPassword, h.Comment)
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "DB List Hosts",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Database Hosts", Body: strings.Split(strings.TrimSpace(buf.String()), "\n")}},
	})
	return nil
}
