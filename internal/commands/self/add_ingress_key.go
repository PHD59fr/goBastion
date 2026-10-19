package self

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"goBastion/internal/commands/account"
	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"log/slog"

	"goBastion/internal/osadapter"
	gosync "goBastion/internal/utils/sync"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// AddIngressKey adds a new ingress SSH key for the current user.
func AddIngressKey(db *gorm.DB, user *models.User, args []string) error {
	const usage = `selfAddIngressKey --key "<type> <base64> [comment]" [--expires <days>]`
	fs := flag.NewFlagSet("selfAddIngressKey", flag.ContinueOnError)
	var pubKey string
	var expiresDays int
	fs.StringVar(&pubKey, "key", "", "SSH public key")
	fs.IntVar(&expiresDays, "expires", 0, "Key expiry in days (0 = never)")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: " + usage}},
			},
		})
		return err
	}
	if expiresDays < 0 {
		return fmt.Errorf("key expiry days cannot be negative")
	}
	if fs.NArg() != 0 {
		msg := "Unexpected extra arguments. Quote the entire --key value. Usage: " + usage
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{msg}},
			},
		})
		return fmt.Errorf("%s", msg)
	}
	// Get the public key from the parsed flags
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{usage}},
			},
		})
		return fmt.Errorf("SSH public key is required")
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey)); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid SSH public key. Supply a complete OpenSSH public key (type and Base64 payload) and quote the entire --key value, including any comment."}},
			},
		})
		return fmt.Errorf("invalid ssh key: %w", err)
	}

	var expiresAt *time.Time
	if expiresDays > 0 {
		expires := time.Now().AddDate(0, 0, expiresDays)
		expiresAt = &expires
	}
	if err := account.CreateDBIngressKey(db, user, pubKey, account.IngressKeyMetadata{ExpiresAt: expiresAt}); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add ingress key. Please contact admin."}},
			},
		})
		return err
	}

	if err := gosync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).IngressKeyFromDB(*user); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to sync ingress key. Please contact admin."}},
			},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Ingress Key",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Ingress key added successfully."}},
		},
	})
	return nil
}
