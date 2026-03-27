package self

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SelfDelIngressKey removes an ingress SSH key for the current user.
func SelfDelIngressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelIngressKey", flag.ContinueOnError)
	var keyId string
	fs.StringVar(&keyId, "id", "", "SSH public key ID")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	if err := fs.Parse(args); err != nil {
		if err.Error() == "invalid access ID format" {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Ingress Key",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Error", Body: []string{"Invalid Ingress Key ID format."}},
				},
			})
		} else {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Ingress Key",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelIngressKey --id <key_id>"}},
				},
			})
		}
		return err
	}
	if strings.TrimSpace(keyId) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelIngressKey --id <key_id>"}},
			},
		})
		return nil
	}
	_, err := uuid.Parse(keyId)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid Ingress Key ID format."}},
			},
		})
		return fmt.Errorf("invalid key UUID: %v", err)
	}
	result := db.Where("id = ? AND user_id = ?", keyId, user.ID).Delete(&models.IngressKey{})
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete the SSH key. Please try again."}},
			},
		})
		return fmt.Errorf("error deleting ingress key %s: %v", keyId, result.Error)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Ingress Key",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Ingress key deleted."}},
		},
	})
	return nil
}
