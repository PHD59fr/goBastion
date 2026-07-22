package self

import (
	"fmt"
	"time"

	"goBastion/internal/models"
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

	var bodyLines []string
	now := time.Now()
	for _, a := range accesses {
		expires := "Never"
		if a.ExpiresAt != nil {
			if a.ExpiresAt.Before(now) {
				expires = "EXPIRED(" + a.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expires = a.ExpiresAt.Format("2006-01-02")
			}
		}
		dbName := a.Database
		if dbName == "" {
			dbName = "*"
		}
		comment := a.Comment
		if comment == "" {
			comment = "-"
		}
		line := fmt.Sprintf("  %s  %s:%d  proto=%s  user=%s  db=%s  expires=%s  %s",
			a.ID.String()[:8], a.Host, a.Port, a.Protocol, a.Username, dbName, expires, comment)
		bodyLines = append(bodyLines, line)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "My Personal DB Accesses",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "DB Accesses", Body: bodyLines},
		},
	})
	return nil
}
