package self

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SelfDelAccess removes a personal SSH access entry for the current user.
func SelfDelAccess(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelAccess", flag.ContinueOnError)
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
				Title:     "Delete Personal Access",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Error", Body: []string{"Invalid access ID format."}},
				},
			})
		} else {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Personal Access",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelAccess --id <access_id>"}},
				},
			})
		}
		return err
	}
	if strings.TrimSpace(fs.Lookup("id").Value.String()) == "" || accessID == uuid.Nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelAccess --id <access_id>"}},
			},
		})
		return nil
	}
	var access models.SelfAccess
	result := db.Where("id = ? AND user_id = ?", accessID, user.ID).First(&access)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No such access found."}},
			},
		})
		return nil
	} else if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Database error while looking up access entry. Please try again."}},
			},
		})
		return fmt.Errorf("database error: %v", result.Error)
	}
	if err := db.Delete(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete personal access. Please contact admin."}},
			},
		})
		return fmt.Errorf("error deleting personal access: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal Access",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Personal access deleted successfully."}},
		},
	})
	return nil
}
