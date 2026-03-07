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

// SelfAddIngressKey adds a new ingress SSH key for the current user.
func SelfAddIngressKey(db *gorm.DB, user *models.User, args []string) error {
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
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfAddIngressKey --key <ssh_public_key> [--expires <days>]"}},
			},
		})
		return err
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "--key" && i+1 < len(args) {
			pubKey = strings.Join(args[i+1:], " ")
			break
		}
	}
	if strings.TrimSpace(pubKey) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddIngressKey --key <ssh_public_key> [--expires <days>]"}},
			},
		})
		return nil
	}

	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey)); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid SSH public key."}},
			},
		})
		return fmt.Errorf("invalid ssh key: %w", err)
	}

	if err := account.CreateDBIngressKey(db, user, pubKey); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add ingress key. Please contact admin."}},
			},
		})
		return err
	}

	// Apply expiry if requested
	if expiresDays > 0 {
		expiresAt := time.Now().AddDate(0, 0, expiresDays)
		if err := db.Model(&models.IngressKey{}).
			Where("user_id = ? AND key = ?", user.ID, strings.TrimSpace(pubKey)).
			Update("expires_at", expiresAt).Error; err != nil {
			// Non-fatal: key was created, just expiry update failed
			fmt.Printf("⚠️  Key added but expiry could not be set: %v\n", err)
		}
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
