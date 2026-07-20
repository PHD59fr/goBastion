package realm

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// List lists configured realms.
func List(db *gorm.DB, currentUser *models.User, args []string) error {
	if !currentUser.CanDo(db, "realmList", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list realms."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var realms []models.Realm
	if err := db.Preload("CreatedBy").Order("name asc").Find(&realms).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to query realms."}}},
		})
		return err
	}
	if len(realms) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Realm List",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"No realms configured."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "Name\tBastion\tEnabled\tAllowed From\tCreated By\tCreated At")
	for _, r := range realms {
		host := strings.TrimSpace(r.BastionHost)
		if host == "" {
			host = r.Name
		}
		port := r.BastionPort
		if port == 0 {
			port = 22
		}
		_, _ = fmt.Fprintf(w, "%s\t%s:%d\t%t\t%s\t%s\t%s\n", r.Name, host, port, r.Enabled, r.AllowedFrom, r.CreatedBy.Username, r.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "Realm List",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Realms", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}
