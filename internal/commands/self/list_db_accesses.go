package self

import (
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListDBAccesses lists all personal database accesses for the current user.
func ListDBAccesses(db *gorm.DB, user *models.User) error {
	var accesses []models.SelfDBAccess
	result := db.Where("user_id = ?", user.ID).Find(&accesses)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal DB Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving DB accesses. Please contact admin."}},
			},
		})
		return result.Error
	}
	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal DB Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "No Accesses Found", Body: []string{"You have not added any personal DB accesses."}},
			},
		})
		return nil
	}
	rows := make([]utils.DBAccessRow, len(accesses))
	for i, a := range accesses {
		rows[i] = utils.SelfDBAccessToRow(a)
	}
	bodyLines := utils.RenderDBAccessTable(rows)

	console.DisplayBlock(console.ContentBlock{
		Title:     "My Personal DB Accesses",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "DB Accesses", Body: bodyLines},
		},
	})
	return nil
}
