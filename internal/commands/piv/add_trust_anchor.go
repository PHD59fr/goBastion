package piv

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddTrustAnchor adds a PIV CA trust anchor (admin only).
// Usage: pivAddTrustAnchor --name <name> --cert <path>
func AddTrustAnchor(db *gorm.DB, currentUser *models.User, args []string) error {
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
		if err != nil {
			return err
		}
		return fmt.Errorf("invalid or missing arguments")
	}

	if !validation.EntityNameRegexp.MatchString(name) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Name", Body: []string{"Name must contain only letters, digits, dots, hyphens, and underscores."}}},
		})
		return fmt.Errorf("invalid trust anchor name: %s", name)
	}

	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Cannot read certificate file: %v", err)}}},
		})
		return fmt.Errorf("read certificate file: %w", err)
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
		return fmt.Errorf("store trust anchor: %w", err)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add PIV Trust Anchor",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Trust anchor '%s' added.", name)}}},
	})
	return nil
}
