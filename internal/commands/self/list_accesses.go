package self

import (
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListAccesses lists all personal SSH accesses for the current user.
func ListAccesses(db *gorm.DB, user *models.User) error {
	var accesses []models.SelfAccess
	result := db.Where("user_id = ?", user.ID).Find(&accesses)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses. Please contact admin."}},
			},
		})
		return result.Error
	}
	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "No Accesses Found", Body: []string{"You have not added any personal accesses."}},
			},
		})
		return nil
	}
	rows := make([]utils.AccessRow, len(accesses))
	for i, a := range accesses {
		rows[i] = utils.SelfAccessToRow(a)
	}
	bodyLines := utils.RenderAccessTable(rows)
	block := console.ContentBlock{
		Title:     "My Personal Accesses",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Accesses", Body: bodyLines},
		},
	}
	console.DisplayBlock(block)
	return nil
}
