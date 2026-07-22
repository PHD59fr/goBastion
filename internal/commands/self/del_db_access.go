package self

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DelDBAccess removes a personal database access entry for the current user.
func DelDBAccess(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelDBAccess", flag.ContinueOnError)
	var accessID uuid.UUID
	fs.Func("id", "Access ID", func(s string) error {
		parsedID, err := uuid.Parse(s)
		if err != nil {
			return fmt.Errorf("invalid access ID format")
		}
		accessID = parsedID
		return nil
	})
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	err := fs.Parse(args)
	if err != nil {
		if strings.Contains(err.Error(), "invalid access ID format") {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Personal DB Access",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Error", Body: []string{"Invalid access ID format."}},
				},
			})
		} else {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Personal DB Access",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelDBAccess --id <access_id>"}},
				},
			})
		}
		return err
	}
	if strings.TrimSpace(fs.Lookup("id").Value.String()) == "" || accessID == uuid.Nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelDBAccess --id <access_id>"}},
			},
		})
		return nil
	}
	var access models.SelfDBAccess
	result := db.Where("id = ? AND user_id = ?", accessID, user.ID).First(&access)
	if result.Error != nil {
		if strings.Contains(result.Error.Error(), "record not found") {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Personal DB Access",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Error", Body: []string{"No such access found."}},
				},
			})
			return nil
		}
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Database error while looking up access entry. Please try again."}},
			},
		})
		return fmt.Errorf("database error: %v", result.Error)
	}
	if err := db.Delete(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete personal DB access. Please contact admin."}},
			},
		})
		return fmt.Errorf("error deleting personal DB access: %w", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal DB Access",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Personal DB access deleted successfully."}},
		},
	})
	return nil
}
