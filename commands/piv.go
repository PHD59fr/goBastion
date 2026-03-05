package commands

import (
	"bytes"
	"flag"
	"fmt"
	"goBastion/models"
	"goBastion/utils/console"
	"goBastion/utils/piv"
	"goBastion/utils/sync"
	"os"
	"strings"
	"text/tabwriter"

	"gorm.io/gorm"
)

// PivAddTrustAnchor adds a PIV CA trust anchor (admin only).
// Usage: pivAddTrustAnchor --name <name> --cert <path>
func PivAddTrustAnchor(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("pivAddTrustAnchor", flag.ContinueOnError)
	var name, certFile string
	fs.StringVar(&name, "name", "", "Friendly name for this trust anchor")
	fs.StringVar(&certFile, "cert", "", "Path to PEM certificate file")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || name == "" || certFile == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: pivAddTrustAnchor --name <name> --cert <path-to-pem>"}}},
		})
		return nil
	}

	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Cannot read certificate file: %v", err)}}},
		})
		return nil
	}

	anchor := models.PIVTrustAnchor{
		Name:      name,
		CertPEM:   string(certBytes),
		AddedByID: currentUser.ID,
	}
	if err := db.Create(&anchor).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Failed to store anchor: %v", err)}}},
		})
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add PIV Trust Anchor",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Trust anchor '%s' added.", name)}}},
	})
	return nil
}

// PivListTrustAnchors lists all registered PIV trust anchors (admin only).
func PivListTrustAnchors(db *gorm.DB, currentUser *models.User, args []string) error {
	var anchors []models.PIVTrustAnchor
	if err := db.Preload("AddedBy").Find(&anchors).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List PIV Trust Anchors",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to query trust anchors."}}},
		})
		return nil
	}

	if len(anchors) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List PIV Trust Anchors",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"No trust anchors configured."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tName\tAdded By\tCreated At")
	for _, a := range anchors {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			a.ID.String(), a.Name, a.AddedBy.Username, a.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "List PIV Trust Anchors",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Anchors", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}

// PivRemoveTrustAnchor removes a PIV trust anchor by name (admin only).
// Usage: pivRemoveTrustAnchor --name <name>
func PivRemoveTrustAnchor(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("pivRemoveTrustAnchor", flag.ContinueOnError)
	var name string
	fs.StringVar(&name, "name", "", "Name of the trust anchor to remove")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || name == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: pivRemoveTrustAnchor --name <name>"}}},
		})
		return nil
	}

	res := db.Where("name = ?", name).Delete(&models.PIVTrustAnchor{})
	if res.Error != nil || res.RowsAffected == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Trust anchor '%s' not found.", name)}}},
		})
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Remove PIV Trust Anchor",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Trust anchor '%s' removed.", name)}}},
	})
	return nil
}

// addIngressKey is a shared helper: calls CreateDBIngressKey and optionally marks the
// resulting IngressKey as PIV-attested before syncing authorized_keys.
func addIngressKey(db *gorm.DB, user *models.User, pubKeyText, comment string, pivAttested bool) error {
	if err := CreateDBIngressKey(db, user, pubKeyText); err != nil {
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
	if err := sync.IngressKeyFromDB(db, *user); err != nil {
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
	var flagOutput bytes.Buffer
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
