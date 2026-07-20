package self

import (
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListIngressKeys lists all ingress SSH keys for the current user.
func ListIngressKeys(db *gorm.DB, user *models.User) error {
	var keys []models.IngressKey
	if err := db.Where("user_id = ?", user.ID).Find(&keys).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Ingress Keys",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving keys. Please contact support."}},
			},
		})
		return err
	}
	if len(keys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Ingress Keys",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No ingress keys found."}},
			},
		})
		return nil
	}
	keySections := utils.RenderIngressKeysTable(keys)
	sections := make([]console.SectionContent, len(keySections))
	for i, ks := range keySections {
		sections[i] = console.SectionContent{SubTitle: ks.SubTitle, Body: ks.Body}
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "My Ingress Keys",
		BlockType: "success",
		Sections:  sections,
	})
	return nil
}
