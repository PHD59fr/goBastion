package account

import (
	"fmt"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// AccountList displays all non-system user accounts.
func AccountList(db *gorm.DB, currentUser *models.User) error {
	var users []models.User
	if err := db.Where("system_user = ?", false).Find(&users).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Database Error", Body: []string{"Unable to fetch users."}},
			},
		})
		return err
	}

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

	sections := make([]console.SectionContent, 0, len(users))
	for _, u := range users {
		var userGroups []models.UserGroup
		if err := db.Preload("Group").Where("user_id = ?", u.ID).Find(&userGroups).Error; err != nil {
			sections = append(sections, console.SectionContent{
				SubTitle: fmt.Sprintf("User: %s", u.Username),
				Body:     []string{"Unable to load groups."},
			})
			continue
		}

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
				role := utils.GetRoles(ug)
				var coloredRole string
				switch role {
				case "Owner":
					coloredRole = utils.BgRedB("Owner")
				case "ACL Keeper":
					coloredRole = utils.BgYellowB("ACL Keeper")
				case "Gate Keeper":
					coloredRole = utils.BgGreenB("Gate Keeper")
				default:
					coloredRole = utils.BgBlueB("Member")
				}

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
