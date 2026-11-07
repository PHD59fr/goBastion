package restricted

import (
	"bytes"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
		if err != nil {
			return err
		}
		return fmt.Errorf("missing required arguments")
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
	err := db.Transaction(func(tx *gorm.DB) error {
		// Serialize grants for this account even on legacy schemas whose
		// unique index includes nullable deleted_at. Never create a second
		// active grant, and never require deleting audit/history rows.
		var owner models.User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&owner, "id = ?", user.ID).Error; err != nil {
			return err
		}
		var existing models.RestrictedCommandGrant
		err := tx.Unscoped().Where("user_id = ? AND command = ?", user.ID, grant.Command).
			Order("deleted_at ASC").First(&existing).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return tx.Create(&grant).Error
		}
		if err != nil {
			return err
		}
		// Explicitly check active rows: NULL ordering differs between engines.
		var active int64
		if err := tx.Model(&models.RestrictedCommandGrant{}).Where("user_id = ? AND command = ?", user.ID, grant.Command).Count(&active).Error; err != nil {
			return err
		}
		if active != 0 {
			return fmt.Errorf("command is already granted to this user")
		}
		return tx.Unscoped().Model(&existing).Where("deleted_at IS NOT NULL").
			Updates(map[string]any{"deleted_at": nil, "granted_by_id": currentUser.ID}).Error
	}, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Restricted Grant Add",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to add grant (it may already exist)."}}},
		})
		return err
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
		if err != nil {
			return err
		}
		return fmt.Errorf("missing required arguments")
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
		return fmt.Errorf("restricted grant not found")
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
		return err
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
