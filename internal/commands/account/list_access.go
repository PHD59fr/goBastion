package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// ListAccess lists all personal SSH accesses for a user.
func ListAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountListAccess", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list accesses")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountListAccess --user <username>"}}},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountListAccess --user <username>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountListAccess", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view accesses for this account."}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", username)}}},
		})
		return err
	}

	var accesses []models.SelfAccess
	if err := db.Where("user_id = ?", user.ID).Find(&accesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses. Please contact support."}}},
		})
		return err
	}

	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Accesses Found", Body: []string{"This user has not added any personal accesses."}}},
		})
		return nil
	}

	rows := make([]utils.AccessRow, len(accesses))
	for i, a := range accesses {
		rows[i] = utils.SelfAccessToRow(a)
	}
	bodyLines := utils.RenderAccessTable(rows)
	console.DisplayBlock(console.ContentBlock{
		Title:     "Access List",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Accesses", Body: bodyLines}},
	})

	return nil
}
