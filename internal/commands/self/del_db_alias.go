package self

import (
	"errors"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DelDBAlias removes a personal database alias.
func DelDBAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelDBAlias", flag.ContinueOnError)
	var aliasID string
	fs.StringVar(&aliasID, "id", "", "Alias ID")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelDBAlias --id <alias_id>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(aliasID) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelDBAlias --id <alias_id>"}},
			},
		})
		return nil
	}
	parsedID, err := uuid.Parse(aliasID)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid alias ID format."}},
			},
		})
		return fmt.Errorf("invalid alias ID format: %w", err)
	}
	var alias models.DatabaseAlias
	result := db.Where("id = ? AND user_id = ?", parsedID, user.ID).First(&alias)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No alias found for the current user with the given ID."}},
			},
		})
		return nil
	} else if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Database error while looking up alias. Please try again."}},
			},
		})
		return validation.WrapDBError(result.Error, "database error while looking up alias")
	}
	if err := db.Delete(&alias).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal DB Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete alias. Please contact admin."}},
			},
		})
		return fmt.Errorf("error deleting alias: %w", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal DB Alias",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Alias deleted successfully."}},
		},
	})
	return nil
}
