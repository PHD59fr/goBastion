package self

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListAccesses lists all personal SSH accesses for the current user.
func ListAccesses(db *gorm.DB, user *models.User) error {
	var accesses []models.SelfAccess
	result := db.Where("user_id = ?", user.ID).Find(&accesses)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses. Please contact admin."}},
			},
		})
		return result.Error
	}
	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "No Accesses Found", Body: []string{"You have not added any personal accesses."}},
			},
		})
		return nil
	}
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tUsername\tServer\tPort\tProtocol\tComment\tFrom\tExpires\tLast Used\tCreated At")
	for _, access := range accesses {
		lastUsed := "Never"
		if !access.LastConnection.IsZero() {
			lastUsed = access.LastConnection.Format("2006-01-02 15:04:05")
		}
		expires := "Never"
		if access.ExpiresAt != nil {
			if access.ExpiresAt.Before(time.Now()) {
				expires = "EXPIRED(" + access.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expires = access.ExpiresAt.Format("2006-01-02")
			}
		}
		allowedFrom := access.AllowedFrom
		if allowedFrom == "" {
			allowedFrom = "*"
		}
		proto := access.Protocol
		if proto == "" {
			proto = "ssh"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			access.ID.String(),
			access.Username,
			access.Server,
			access.Port,
			proto,
			access.Comment,
			allowedFrom,
			expires,
			lastUsed,
			access.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()
	tableOutput := buf.String()
	bodyLines := strings.Split(strings.TrimSpace(tableOutput), "\n")
	block := console.ContentBlock{
		Title:     "My Personal Accesses",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Accesses", Body: bodyLines},
		},
	}
	console.DisplayBlock(block)
	return nil
}
