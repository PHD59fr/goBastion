package self

import (
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListEgressKeys lists all egress SSH keys for the current user.
func ListEgressKeys(db *gorm.DB, user *models.User) error {
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
	keySections := utils.RenderEgressKeysTable(keys)
	sections := make([]console.SectionContent, len(keySections))
	for i, ks := range keySections {
		sections[i] = console.SectionContent{SubTitle: ks.SubTitle, Body: ks.Body}
	}
	block := console.ContentBlock{
		Title:     "My Egress Keys",
		BlockType: "success",
		Sections:  sections,
	}
	console.DisplayBlock(block)
	return nil
}
