package realm

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// RealmDelete removes a realm configuration.
func RealmDelete(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("realmDelete", flag.ContinueOnError)
	var realmName string
	fs.StringVar(&realmName, "realm", "", "Realm name")
	var out bytes.Buffer
	fs.SetOutput(&out)
	if err := fs.Parse(args); err != nil || strings.TrimSpace(realmName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: realmDelete --realm <name>"}}},
		})
		return nil
	}

	res := db.Where("name = ?", strings.ToLower(strings.TrimSpace(realmName))).Delete(&models.Realm{})
	if res.Error != nil || res.RowsAffected == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("Realm '%s' not found.", realmName)}}},
		})
		if res.Error != nil {
			return res.Error
		}
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Realm Delete",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Realm '%s' removed.", realmName)}}},
	})
	return nil
}
