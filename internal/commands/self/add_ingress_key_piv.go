package self

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"goBastion/internal/commands/account"
	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/piv"
	"log/slog"

	"goBastion/internal/osadapter"
	gosync "goBastion/internal/utils/sync"

	"gorm.io/gorm"
)

// addIngressKey is a shared helper: calls CreateDBIngressKey and optionally marks the
// resulting IngressKey as PIV-attested before syncing authorized_keys.
func addIngressKey(db *gorm.DB, user *models.User, pubKeyText, comment string, pivAttested bool) error {
	if err := account.CreateDBIngressKey(db, user, pubKeyText); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Failed to add key: %v", err)}}},
		})
		return nil
	}

	if pivAttested {
		if err := db.Model(&models.IngressKey{}).
			Where("user_id = ? AND key = ?", user.ID, strings.TrimSpace(pubKeyText)).
			Update("piv_attested", true).Error; err != nil {
			fmt.Printf("Warning: key added but PIV attestation flag could not be set: %v\n", err)
		}
	}

	// Re-sync authorized_keys
	if err := gosync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).IngressKeyFromDB(*user); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to sync authorized_keys."}}},
		})
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add PIV Ingress Key",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"PIV-attested ingress key added successfully."}}},
	})
	return nil
}

// The full attestation chain is verified against a stored trust anchor before
// the key is accepted.
//
// Usage: selfAddIngressKeyPIV --attest <path> --intermediate <path> [--comment <comment>]
func SelfAddIngressKeyPIV(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddIngressKeyPIV", flag.ContinueOnError)
	var attestFile, intermediateFile, comment string
	fs.StringVar(&attestFile, "attest", "", "Path to PIV attestation certificate (PEM)")
	fs.StringVar(&intermediateFile, "intermediate", "", "Path to intermediate certificate (PEM)")
	fs.StringVar(&comment, "comment", "", "Comment for this key")
	var flagOutput strings.Builder
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || attestFile == "" || intermediateFile == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Usage", Body: []string{
				"Usage: selfAddIngressKeyPIV --attest <path> --intermediate <path> [--comment <comment>]",
				"",
				"Generate attestation data on a YubiKey:",
				"  yubico-piv-tool --action=attest --slot=9a > attest.pem",
				"  yubico-piv-tool --action=read-cert --slot=f9 > intermediate.pem",
			}}},
		})
		return nil
	}

	attestPEM, err := os.ReadFile(attestFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Cannot read attest file: %v", err)}}},
		})
		return nil
	}

	intermediatePEM, err := os.ReadFile(intermediateFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Cannot read intermediate file: %v", err)}}},
		})
		return nil
	}

	// Remaining args after flags is the SSH public key text
	sshKeyText := strings.Join(fs.Args(), " ")
	if sshKeyText == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Please provide the SSH public key as the last argument."}}},
		})
		return nil
	}

	// Load all trust anchors from DB and find one that validates the chain.
	var anchors []models.PIVTrustAnchor
	if err := db.Find(&anchors).Error; err != nil || len(anchors) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"No PIV trust anchors configured. An admin must add one first with pivAddTrustAnchor."}}},
		})
		return nil
	}

	var verifyErr error
	for _, anchor := range anchors {
		verifyErr = piv.VerifyAttestation(anchor.CertPEM, string(intermediatePEM), string(attestPEM), sshKeyText)
		if verifyErr == nil {
			break
		}
	}
	if verifyErr != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Attestation Failed", Body: []string{verifyErr.Error()}}},
		})
		return nil
	}

	// Attestation OK - add the key, marked as PIV-attested.
	return addIngressKey(db, currentUser, sshKeyText, comment, true)
}
