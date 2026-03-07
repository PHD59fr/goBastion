package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// AccountListAccess lists all personal SSH accesses for a user.
func AccountListAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountListAccess", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list accesses")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountListAccess --user <username>"}}},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountListAccess --user <username>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountListAccess", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view accesses for this account."}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
		})
		return err
	}

	var accesses []models.SelfAccess
	if err := db.Where("user_id = ?", user.ID).Find(&accesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses. Please contact support."}}},
		})
		return err
	}

	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Accesses Found", Body: []string{"This user has not added any personal accesses."}}},
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
		expiresStr := "Never"
		if access.ExpiresAt != nil {
			if access.ExpiresAt.Before(time.Now()) {
				expiresStr = "EXPIRED(" + access.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expiresStr = access.ExpiresAt.Format("2006-01-02")
			}
		}
		fromStr := access.AllowedFrom
		if fromStr == "" {
			fromStr = "*"
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
			fromStr,
			expiresStr,
			lastUsed,
			access.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()
	tableOutput := buf.String()
	bodyLines := strings.Split(strings.TrimSpace(tableOutput), "\n")
	console.DisplayBlock(console.ContentBlock{
		Title:     "Access List",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Accesses", Body: bodyLines}},
	})

	return nil
}
