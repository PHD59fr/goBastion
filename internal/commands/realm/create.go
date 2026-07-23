package realm

import (
	"bytes"
	"flag"
	"fmt"
	"regexp"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

var realmNameRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Create registers a trusted external bastion realm.
func Create(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("realmCreate", flag.ContinueOnError)
	var realmName, bastionHost, allowedFrom, publicKey string
	var bastionPort int64
	fs.StringVar(&realmName, "realm", "", "Realm name")
	fs.StringVar(&bastionHost, "bastion", "", "Remote bastion hostname/IP")
	fs.Int64Var(&bastionPort, "port", 22, "Remote bastion SSH port")
	fs.StringVar(&allowedFrom, "from", "", "Trusted source CIDRs (comma-separated)")
	fs.StringVar(&publicKey, "public-key", "", "Trusted remote bastion public key")
	var out bytes.Buffer
	fs.SetOutput(&out)

	if err := fs.Parse(args); err != nil ||
		strings.TrimSpace(realmName) == "" ||
		strings.TrimSpace(bastionHost) == "" ||
		strings.TrimSpace(allowedFrom) == "" ||
		strings.TrimSpace(publicKey) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: realmCreate --realm <name> --bastion <host> [--port <22>] --from <cidrs> --public-key <ssh-pubkey>"}}},
		})
		if err != nil {
			return err
		}
		return fmt.Errorf("missing required arguments")
	}

	realmName = strings.ToLower(strings.TrimSpace(realmName))
	if !realmNameRegexp.MatchString(realmName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Name", Body: []string{"Realm name must match ^[a-z0-9][a-z0-9._-]{0,63}$"}}},
		})
		return nil
	}
	bastionHost = strings.TrimSpace(bastionHost)
	if !validation.IsValidHost(bastionHost) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Bastion Host", Body: []string{"--bastion must be a valid hostname or IP"}}},
		})
		return nil
	}
	if !validation.IsValidPort(bastionPort) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Bastion Port", Body: []string{"--port must be between 1 and 65535"}}},
		})
		return nil
	}
	if !validation.IsValidCIDRs(allowedFrom) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid CIDRs", Body: []string{"--from must be valid comma-separated CIDRs"}}},
		})
		return nil
	}
	publicKey = strings.TrimSpace(publicKey)
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKey)); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Key", Body: []string{"--public-key must be an SSH public key"}}},
		})
		return fmt.Errorf("invalid realm public key: %w", err)
	}

	var existing models.Realm
	if err := db.Where("name = ?", realmName).First(&existing).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{fmt.Sprintf("Realm '%s' already exists.", realmName)}}},
		})
		return nil
	}

	record := models.Realm{
		Name:        realmName,
		BastionHost: bastionHost,
		BastionPort: bastionPort,
		AllowedFrom: strings.TrimSpace(allowedFrom),
		PublicKey:   publicKey,
		Enabled:     true,
		CreatedByID: currentUser.ID,
	}
	if err := db.Create(&record).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to create realm."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Realm Create",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("Realm '%s' created.", realmName),
			fmt.Sprintf("Remote bastion endpoint: %s:%d", bastionHost, bastionPort),
		}}},
	})
	return nil
}
