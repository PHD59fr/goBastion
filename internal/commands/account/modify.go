package account

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/system"

	"gorm.io/gorm"
)

// The helper reloads committed policy under the root reconciliation lock.
var syncModifiedAccount = func(username string) error {
	_, err := system.ExecCommand("/usr/bin/sudo", "-n", "/usr/local/sbin/gobastion-sync-user", username)
	return err
}

// Modify updates the system role of a user account.
func Modify(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountModify", flag.ContinueOnError)
	var username, newRole, oshOnlyRaw, superOwnerRaw string
	fs.StringVar(&username, "user", "", "Username to modify")
	fs.StringVar(&newRole, "sysrole", "", "New system role (admin or user)")
	fs.StringVar(&oshOnlyRaw, "oshOnly", "", "Set osh-only mode: true or false")
	fs.StringVar(&superOwnerRaw, "superOwner", "", "Set superowner mode: true or false")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountModify --user <username> [--sysrole <admin|user>] [--oshOnly <true|false>] [--superOwner <true|false>]"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" || (strings.TrimSpace(newRole) == "" && strings.TrimSpace(oshOnlyRaw) == "" && strings.TrimSpace(superOwnerRaw) == "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountModify --user <username> [--sysrole <admin|user>] [--oshOnly <true|false>] [--superOwner <true|false>]"}}},
		})
		return fmt.Errorf("missing required arguments")
	}

	if !currentUser.CanDo(db, "accountModify", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to modify this account."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	newRole = strings.ToLower(strings.TrimSpace(newRole))
	if newRole != "" && newRole != "admin" && newRole != "user" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid System Role", Body: []string{"System role must be 'admin' or 'user'."}}},
		})
		return fmt.Errorf("invalid system role: %s", newRole)
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", username)}}},
		})
		return err
	}

	if newRole != "" {
		u.Role = newRole
	}
	if strings.TrimSpace(oshOnlyRaw) != "" {
		v, err := parseBoolFlag(oshOnlyRaw)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Modify",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid oshOnly", Body: []string{"--oshOnly must be true or false"}}},
			})
			return err
		}
		u.OSHOnly = v
	}
	if strings.TrimSpace(superOwnerRaw) != "" {
		v, err := parseBoolFlag(superOwnerRaw)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Modify",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid superOwner", Body: []string{"--superOwner must be true or false"}}},
			})
			return err
		}
		u.SuperOwner = v
	}

	if err := withAccountChange(db, func(tx *gorm.DB) error {
		var fresh models.User
		if err := tx.First(&fresh, "id = ?", u.ID).Error; err != nil {
			return err
		}
		if fresh.IsAdmin() && newRole == models.RoleUser {
			if err := requireOtherAdmin(tx, &fresh); err != nil {
				return err
			}
		}
		changes := map[string]any{}
		if newRole != "" {
			changes["role"] = newRole
		}
		if strings.TrimSpace(oshOnlyRaw) != "" {
			changes["osh_only"] = u.OSHOnly
		}
		if strings.TrimSpace(superOwnerRaw) != "" {
			changes["super_owner"] = u.SuperOwner
		}
		if err := tx.Model(&fresh).Updates(changes).Error; err != nil {
			return err
		}
		u = fresh
		return nil
	}); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title: "Account Modify", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Blocked", Body: []string{err.Error()}}},
		})
		return err
	}

	if err := syncModifiedAccount(u.Username); err != nil {
		log := slog.Default()
		log.Error("account_reconciliation_failed", slog.String("user", u.Username), slog.String("error", err.Error()))
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "warning",
			Sections:  []console.SectionContent{{SubTitle: "Warning", Body: []string{fmt.Sprintf("User role updated but privileged account/recording access reconciliation failed: %v. Contact your admin.", err)}}},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Modify",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("User '%s' updated.", username),
			fmt.Sprintf("system role: %s", u.Role),
			fmt.Sprintf("osh-only: %t", u.OSHOnly),
			fmt.Sprintf("superowner: %t", u.SuperOwner),
		}}},
	})

	return nil
}

func parseBoolFlag(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", value)
	}
}
