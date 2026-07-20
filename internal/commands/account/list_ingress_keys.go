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

// ListIngressKeys lists all ingress SSH keys for a user.
func ListIngressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountListIngressKeys", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list ingress keys")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Ingress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountListIngressKeys --user <username>"}}},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Ingress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountListIngressKeys --user <username>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountListIngressKeys", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Ingress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view ingress keys for this account."}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Ingress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", username)}}},
		})
		return err
	}

	var ingressKeys []models.IngressKey
	if err := db.Where("user_id = ?", user.ID).Find(&ingressKeys).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Ingress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to fetch ingress keys."}}},
		})
		return err
	}

	if len(ingressKeys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Ingress Keys List",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"No ingress keys found."}}},
		})
		return nil
	}

	keySections := utils.RenderIngressKeysTable(ingressKeys)
	sections := make([]console.SectionContent, len(keySections))
	for i, ks := range keySections {
		sections[i] = console.SectionContent{SubTitle: ks.SubTitle, Body: ks.Body}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Ingress Keys List",
		BlockType: "success",
		Sections:  sections,
	})

	return nil
}
