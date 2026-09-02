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

// addIngressKey persists the key and its attestation metadata before syncing authorized_keys.
func addIngressKey(db *gorm.DB, user *models.User, pubKeyText, comment string, pivAttested bool) error {
	if err := account.CreateDBIngressKey(db, user, pubKeyText, account.IngressKeyMetadata{PIVAttested: pivAttested}); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Failed to add key: %v", err)}}},
		})
		return fmt.Errorf("failed to add ingress key: %w", err)
	}

	// Re-sync authorized_keys
	if err := gosync.New(db, osadapter.NewLinuxAdapter(), *slog.Default()).IngressKeyFromDB(*user); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to sync authorized_keys."}}},
		})
		return fmt.Errorf("failed to sync authorized_keys: %w", err)
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
func AddIngressKeyPIV(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddIngressKeyPIV", flag.ContinueOnError)
	var attestFile, intermediateFile, comment string
	fs.StringVar(&attestFile, "attest", "", "Path to PIV attestation certificate (PEM)")
	fs.StringVar(&intermediateFile, "intermediate", "", "Path to intermediate certificate (PEM)")
	fs.StringVar(&comment, "comment", "", "Comment for this key")
	var flagOutput strings.Builder
	fs.SetOutput(&flagOutput)

	parseErr := fs.Parse(args)
	if parseErr != nil || attestFile == "" || intermediateFile == "" {
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
		if parseErr != nil {
			return parseErr
		}
		return fmt.Errorf("attestation and intermediate certificate files are required")
	}

	attestPEM, err := os.ReadFile(attestFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Cannot read attest file: %v", err)}}},
		})
		return fmt.Errorf("cannot read attest file: %w", err)
	}

	intermediatePEM, err := os.ReadFile(intermediateFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Cannot read intermediate file: %v", err)}}},
		})
		return fmt.Errorf("cannot read intermediate file: %w", err)
	}

	// Remaining args after flags is the SSH public key text
	sshKeyText := strings.Join(fs.Args(), " ")
	if sshKeyText == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Please provide the SSH public key as the last argument."}}},
		})
		return fmt.Errorf("SSH public key is required")
	}

	// Load all trust anchors from DB and find one that validates the chain.
	var anchors []models.PIVTrustAnchor
	if err := db.Find(&anchors).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to load PIV trust anchors. Please contact admin."}}},
		})
		return fmt.Errorf("failed to load PIV trust anchors: %w", err)
	}
	if len(anchors) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Ingress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"No PIV trust anchors configured. An admin must add one first with pivAddTrustAnchor."}}},
		})
		return fmt.Errorf("no PIV trust anchors configured")
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
		return fmt.Errorf("PIV attestation failed: %w", verifyErr)
	}

	// Attestation OK - add the key, marked as PIV-attested.
	return addIngressKey(db, currentUser, sshKeyText, comment, true)
}
