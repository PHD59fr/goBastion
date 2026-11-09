package piv

import (
	"bytes"
	"flag"
	"fmt"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// RemoveTrustAnchor removes a PIV trust anchor by name (admin only).
// Usage: pivRemoveTrustAnchor --name <name>
func RemoveTrustAnchor(db *gorm.DB, currentUser *models.User, args []string) error {
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
		if err != nil {
			return err
		}
		return fmt.Errorf("invalid or missing arguments")
	}

	res := db.Where("name = ?", name).Delete(&models.PIVTrustAnchor{})
	if res.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Trust anchor '%s' not found.", name)}}},
		})
		return fmt.Errorf("remove trust anchor: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove PIV Trust Anchor",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Trust anchor '%s' not found.", name)}}},
		})
		// Idempotent: removing an absent anchor reports the condition but does
		// not fail scripts that already achieved the desired state.
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Remove PIV Trust Anchor",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Trust anchor '%s' removed.", name)}}},
	})
	return nil
}
