package self

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SelfDelAlias removes a personal alias.
func SelfDelAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelAlias", flag.ContinueOnError)
	var hostID string
	fs.StringVar(&hostID, "id", "", "Alias ID")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelAlias --id <alias_id>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(hostID) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelAlias --id <alias_id>"}},
			},
		})
		return nil
	}
	parsedID, err := uuid.Parse(hostID)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid alias ID format."}},
			},
		})
		return fmt.Errorf("invalid alias ID format: %v", err)
	}
	var host models.Aliases
	result := db.Where("id = ? AND user_id = ?", parsedID, user.ID).First(&host)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No alias found for the current user with the given ID."}},
			},
		})
		return nil
	} else if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Database error while looking up alias. Please try again."}},
			},
		})
		return fmt.Errorf("database error: %v", result.Error)
	}
	if err := db.Delete(&host).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete alias. Please contact admin."}},
			},
		})
		return fmt.Errorf("error deleting alias: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal Alias",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Alias deleted successfully."}},
		},
	})
	return nil
}
