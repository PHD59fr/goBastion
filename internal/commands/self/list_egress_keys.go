package self

import (
	"fmt"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// SelfListEgressKeys lists all egress SSH keys for the current user.
func SelfListEgressKeys(db *gorm.DB, user *models.User) error {
	var keys []models.SelfEgressKey
	result := db.Where("user_id = ?", user.ID).Find(&keys)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Egress Keys",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving keys. Please contact support."}},
			},
		})
		return result.Error
	}
	if len(keys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Egress Keys",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No Egress keys found."}},
			},
		})
		return nil
	}
	var sections []console.SectionContent
	for _, key := range keys {
		section := console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.PubKey),
			},
		}
		sections = append(sections, section)
	}
	block := console.ContentBlock{
		Title:     "My Egress Keys",
		BlockType: "success",
		Sections:  sections,
	}
	console.DisplayBlock(block)
	return nil
}
