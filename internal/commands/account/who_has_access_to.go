package account

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// WhoHasAccessTo lists all users and groups that have access to a given server.
func WhoHasAccessTo(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("whoHasAccessTo", flag.ContinueOnError)
	var server string
	fs.StringVar(&server, "server", "", "Server to check access for")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: whoHasAccessTo --server <server>"}}},
		})
		return err
	}
	if strings.TrimSpace(server) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: whoHasAccessTo --server <server>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "whoHasAccessTo", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view accesses for this server."}}},
		})
		return nil
	}

	// Load all accesses and filter in Go (supports CIDR matching)
	var allSelfAccesses []models.SelfAccess
	if err := db.Preload("User", "deleted_at IS NULL").Where("deleted_at IS NULL").Find(&allSelfAccesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses."}}},
		})
		return err
	}

	var allGroupAccesses []models.GroupAccess
	if err := db.Preload("Group", "deleted_at IS NULL").Where("deleted_at IS NULL").Find(&allGroupAccesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving group accesses."}}},
		})
		return err
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', tabwriter.StripEscape)
	_, _ = fmt.Fprintln(w, "Type\tName\tUsername\tRole\tServer")
	for _, access := range allSelfAccesses {
		if !serverMatchesQuery(access.Server, server) {
			continue
		}
		if access.User.ID != uuid.Nil {
			_, _ = fmt.Fprintf(w, "User\t-\t%s\t-\t%s\n", access.User.Username, access.Server)
		}
	}

	for _, ga := range allGroupAccesses {
		if !serverMatchesQuery(ga.Server, server) {
			continue
		}
		var userGroups []models.UserGroup
		if err := db.Preload("User", "deleted_at IS NULL").
			Where("group_id = ? AND deleted_at IS NULL", ga.GroupID).
			Find(&userGroups).Error; err != nil {
			continue
		}

		for _, ug := range userGroups {
			if ug.User.ID == uuid.Nil {
				continue
			}

			role := utils.GetRoles(ug)
			var coloredRole string
			switch role {
			case "Owner":
				coloredRole = utils.BgRedB("Owner")
			case "ACL Keeper":
				coloredRole = utils.BgYellowB("ACL Keeper")
			case "Gate Keeper":
				coloredRole = utils.BgGreenB("Gate Keeper")
			default:
				coloredRole = utils.BgBlueB("Member")
			}

			_, _ = fmt.Fprintf(w, "Group\t%s\t%s\t%-12s\t%s\n",
				ga.Group.Name,
				ug.User.Username,
				coloredRole,
				ga.Server,
			)
		}
	}

	_ = w.Flush()
	tableOutput := buf.String()
	bodyLines := strings.Split(strings.TrimSpace(tableOutput), "\n")

	console.DisplayBlock(console.ContentBlock{
		Title:     "Who Has Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: fmt.Sprintf("Accesses to %s", server), Body: bodyLines}},
	})

	return nil
}

// serverMatchesQuery returns true if the stored server string matches the query.
// Supports exact match, substring match, and CIDR containment:
// - If query is an IP and storedServer is a CIDR, checks if the IP is in the CIDR.
// - If storedServer is an IP/hostname and query is a CIDR, checks if the server IP is in the CIDR.
func serverMatchesQuery(storedServer, query string) bool {
	// Exact or substring match
	if strings.Contains(storedServer, query) || strings.Contains(query, storedServer) {
		return true
	}
	queryIP := net.ParseIP(query)
	storedIP := net.ParseIP(storedServer)
	// Query is an IP, stored is a CIDR
	if queryIP != nil {
		_, storedCIDR, err := net.ParseCIDR(storedServer)
		if err == nil && storedCIDR.Contains(queryIP) {
			return true
		}
	}
	// Query is a CIDR, stored is an IP
	if storedIP != nil {
		_, queryCIDR, err := net.ParseCIDR(query)
		if err == nil && queryCIDR.Contains(storedIP) {
			return true
		}
	}
	return false
}
