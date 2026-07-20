package realm

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// Info prints details for one realm.
func Info(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("realmInfo", flag.ContinueOnError)
	var realmName string
	fs.StringVar(&realmName, "realm", "", "Realm name")
	var out bytes.Buffer
	fs.SetOutput(&out)
	if err := fs.Parse(args); err != nil || strings.TrimSpace(realmName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: realmInfo --realm <name>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "realmInfo", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view realm info."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var realm models.Realm
	if err := db.Preload("CreatedBy").Where("name = ?", strings.ToLower(strings.TrimSpace(realmName))).First(&realm).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Realm '%s' not found.", realmName)}}},
		})
		return err
	}

	pub := realm.PublicKey
	if len(pub) > 80 {
		pub = pub[:80] + "..."
	}
	host := strings.TrimSpace(realm.BastionHost)
	if host == "" {
		host = realm.Name
	}
	port := realm.BastionPort
	if port == 0 {
		port = 22
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Realm Info",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Details", Body: []string{
			fmt.Sprintf("ID: %s", realm.ID.String()),
			fmt.Sprintf("Name: %s", realm.Name),
			fmt.Sprintf("Bastion: %s:%d", host, port),
			fmt.Sprintf("Enabled: %t", realm.Enabled),
			fmt.Sprintf("Allowed From: %s", realm.AllowedFrom),
			fmt.Sprintf("Public Key: %s", pub),
			fmt.Sprintf("Created By: %s", realm.CreatedBy.Username),
			fmt.Sprintf("Created At: %s", realm.CreatedAt.Format("2006-01-02 15:04:05")),
		}}},
	})
	return nil
}
