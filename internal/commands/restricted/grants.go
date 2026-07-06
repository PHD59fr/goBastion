package restricted

import (
	"bytes"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

func normalizeCommandName(cmd string) string {
	return strings.TrimSpace(cmd)
}

// GrantAdd grants a restricted command to a target user.
func GrantAdd(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("restrictedGrantAdd", flag.ContinueOnError)
	var username, command string
	fs.StringVar(&username, "user", "", "Target username")
	fs.StringVar(&command, "command", "", "Restricted command name")
	var out bytes.Buffer
	fs.SetOutput(&out)
	if err := fs.Parse(args); err != nil || strings.TrimSpace(username) == "" || strings.TrimSpace(command) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant Add",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: restrictedGrantAdd --user <username> --command <command>"}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", strings.ToLower(strings.TrimSpace(username))).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant Add",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", username)}}},
		})
		return err
	}

	grant := models.RestrictedCommandGrant{
		UserID:      user.ID,
		Command:     normalizeCommandName(command),
		GrantedByID: currentUser.ID,
	}
	if err := db.Create(&grant).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant Add",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to add grant (it may already exist)."}}},
		})
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Restricted Grant Add",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Granted command '%s' to user '%s'.", grant.Command, user.Username)}}},
	})
	return nil
}

// GrantDel removes a restricted command grant from a target user.
func GrantDel(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("restrictedGrantDel", flag.ContinueOnError)
	var username, command string
	fs.StringVar(&username, "user", "", "Target username")
	fs.StringVar(&command, "command", "", "Restricted command name")
	var out bytes.Buffer
	fs.SetOutput(&out)
	if err := fs.Parse(args); err != nil || strings.TrimSpace(username) == "" || strings.TrimSpace(command) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant Del",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: restrictedGrantDel --user <username> --command <command>"}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", strings.ToLower(strings.TrimSpace(username))).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant Del",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", username)}}},
		})
		return err
	}

	res := db.Where("user_id = ? AND command = ?", user.ID, normalizeCommandName(command)).Delete(&models.RestrictedCommandGrant{})
	if res.Error != nil || res.RowsAffected == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant Del",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Grant not found."}}},
		})
		if res.Error != nil {
			return res.Error
		}
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Restricted Grant Del",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Removed grant '%s' from user '%s'.", normalizeCommandName(command), user.Username)}}},
	})
	return nil
}

// GrantList lists restricted command grants, optionally filtered by user.
func GrantList(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("restrictedGrantList", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Optional username filter")
	var out bytes.Buffer
	fs.SetOutput(&out)
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: restrictedGrantList [--user <username>]"}}},
		})
		return nil
	}

	query := db.Preload("User").Preload("GrantedBy").Order("created_at desc")
	if strings.TrimSpace(username) != "" {
		var user models.User
		if err := db.Where("username = ?", strings.ToLower(strings.TrimSpace(username))).First(&user).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Restricted Grant List",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", username)}}},
			})
			return err
		}
		query = query.Where("user_id = ?", user.ID)
	}

	var grants []models.RestrictedCommandGrant
	if err := query.Find(&grants).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to query restricted grants."}}},
		})
		return err
	}
	if len(grants) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant List",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"No restricted grants found."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "User\tCommand\tGranted By\tCreated At")
	for _, g := range grants {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", g.User.Username, g.Command, g.GrantedBy.Username, g.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "Restricted Grant List",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Grants", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}
