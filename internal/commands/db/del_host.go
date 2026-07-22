package db

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

// DelHost soft-deletes a DatabaseHost by name or ID.
func DelHost(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("dbDelHost", flag.ContinueOnError)
	var name string
	var id string
	fs.StringVar(&name, "name", "", "Host alias")
	fs.StringVar(&id, "id", "", "Host UUID")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Del Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: dbDelHost --name <name> | --id <uuid>"}}},
		})
		return err
	}

	if strings.TrimSpace(name) == "" && strings.TrimSpace(id) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Del Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Missing Required Flag", Body: []string{"Either --name or --id is required."}}},
		})
		return fmt.Errorf("missing required flag")
	}

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Del Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only administrators can delete database hosts."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var result *gorm.DB
	if strings.TrimSpace(id) != "" {
		hostUUID, err := uuid.Parse(id)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "DB Del Host",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid UUID", Body: []string{fmt.Sprintf("Invalid UUID: %s", id)}}},
			})
			return err
		}
		result = db.Where("id = ?", hostUUID).Delete(&models.DatabaseHost{})
	} else {
		result = db.Where("name = ? AND deleted_at IS NULL", name).Delete(&models.DatabaseHost{})
	}

	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Del Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to delete database host."}}},
		})
		return result.Error
	}
	if result.RowsAffected == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Del Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Database host '%s' not found.", name)}}},
		})
		return fmt.Errorf("database host not found")
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "DB Del Host",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Database host '%s' deleted successfully.", name)}}},
	})
	return nil
}
