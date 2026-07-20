package account

import (
	"fmt"
	internaldb "goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// List displays all non-system user accounts.
func List(db *gorm.DB, currentUser *models.User) error {
	if !currentUser.CanDo(db, "accountList", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to view the account list."}},
			},
		})
		return nil
	}

	var users []models.User
	if err := db.Where(internaldb.BoolFalseExpr(db, "system_user")).Find(&users).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Database Error", Body: []string{"Unable to fetch users."}},
			},
		})
		return err
	}

	if len(users) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account List",
			BlockType: "info",
			Sections: []console.SectionContent{
				{SubTitle: "Information", Body: []string{"No accounts found."}},
			},
		})
		return nil
	}

	// Batch-load all UserGroup records in a single query to avoid N+1.
	var allUserGroups []models.UserGroup
	if err := db.Preload("Group").Find(&allUserGroups).Error; err != nil {
		allUserGroups = nil
	}
	groupsByUser := make(map[uuid.UUID][]models.UserGroup, len(users))
	for _, ug := range allUserGroups {
		groupsByUser[ug.UserID] = append(groupsByUser[ug.UserID], ug)
	}

	sections := make([]console.SectionContent, 0, len(users))
	for _, u := range users {
		userGroups := groupsByUser[u.ID]

		userInfo := []string{
			fmt.Sprintf("Username: %s", u.Username),
			fmt.Sprintf("System Role: %s", u.Role),
			fmt.Sprintf("Created At: %s", u.CreatedAt.Format("2006-01-02 15:04:05")),
			fmt.Sprintf("Last Login: %s", u.LastLoginAt),
			fmt.Sprintf("Last Login From: %s", u.LastLoginFrom),
		}

		if len(userGroups) > 0 {
			groupLines := []string{"Groups:"}
			for _, ug := range userGroups {
				coloredRole := utils.RoleColor(ug)

				groupLines = append(groupLines, fmt.Sprintf("  - %s - %s", ug.Group.Name, coloredRole))
			}
			userInfo = append(userInfo, groupLines...)
		}

		sections = append(sections, console.SectionContent{
			SubTitle: fmt.Sprintf("User: %s", u.Username),
			Body:     userInfo,
		})
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account List",
		BlockType: "success",
		Sections:  sections,
	})

	return nil
}
