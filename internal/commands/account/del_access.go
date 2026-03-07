package account

import (
	"bytes"
	"flag"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// AccountDelAccess removes a personal SSH access entry by ID.
func AccountDelAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountDelAccess", flag.ContinueOnError)
	var accessID string
	fs.StringVar(&accessID, "access", "", "Access ID to remove")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountDelAccess --access <access_id>"}}},
		})
		return err
	}

	if strings.TrimSpace(accessID) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountDelAccess --access <access_id>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountDelAccess", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete personal access."}}},
		})
		return nil
	}

	if err := db.Where("id = ?", accessID).Delete(&models.SelfAccess{}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to delete personal access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Personal access deleted successfully."}}},
	})

	return nil
}
