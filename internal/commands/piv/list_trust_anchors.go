package piv

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// PivListTrustAnchors lists all registered PIV trust anchors (admin only).
func PivListTrustAnchors(db *gorm.DB, currentUser *models.User, args []string) error {
	var anchors []models.PIVTrustAnchor
	if err := db.Preload("AddedBy").Find(&anchors).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List PIV Trust Anchors",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to query trust anchors."}}},
		})
		return nil
	}

	if len(anchors) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List PIV Trust Anchors",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"No trust anchors configured."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tName\tAdded By\tCreated At")
	for _, a := range anchors {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			a.ID.String(), a.Name, a.AddedBy.Username, a.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "List PIV Trust Anchors",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Anchors", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}
