package self

import (
	"fmt"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// SelfListIngressKeys lists all ingress SSH keys for the current user.
func SelfListIngressKeys(db *gorm.DB, user *models.User) error {
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
	var sections []console.SectionContent
	for _, key := range keys {
		expiresStr := "Never"
		if key.ExpiresAt != nil {
			if key.ExpiresAt.Before(time.Now()) {
				expiresStr = "⚠️ EXPIRED (" + key.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expiresStr = key.ExpiresAt.Format("2006-01-02")
			}
		}
		pivStr := ""
		if key.PIVAttested {
			pivStr = " 🔐 PIV-attested"
		}
		section := console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s%s", key.Type, pivStr),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Expires: %s", expiresStr),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.Key),
			},
		}
		sections = append(sections, section)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "My Ingress Keys",
		BlockType: "success",
		Sections:  sections,
	})
	return nil
}
