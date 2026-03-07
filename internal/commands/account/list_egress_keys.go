package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// AccountListEgressKeys lists all egress SSH keys for a user.
func AccountListEgressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountListEgressKeys", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list egress keys")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountListEgressKeys --user <username>"}}},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountListEgressKeys --user <username>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountListEgressKeys", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view egress keys for this account."}}},
		})
		return fmt.Errorf("access denied")
	}

	var targetUser models.User
	if err := db.Where("username = ?", username).First(&targetUser).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
		})
		return err
	}

	var egressKeys []models.SelfEgressKey
	if err := db.Where("user_id = ?", targetUser.ID).Find(&egressKeys).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to fetch egress keys."}}},
		})
		return err
	}

	if len(egressKeys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"No egress keys found."}}},
		})
		return nil
	}

	sections := make([]console.SectionContent, len(egressKeys))
	for i, key := range egressKeys {
		sections[i] = console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.PubKey),
			},
		}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Egress Keys List",
		BlockType: "success",
		Sections:  sections,
	})

	return nil
}
