package commands

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"goBastion/utils/console"
	"log/slog"
	"net"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"goBastion/utils"
	"goBastion/utils/system"

	"goBastion/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"gorm.io/gorm"
)

// AccountList displays all non-system user accounts.
func AccountList(db *gorm.DB, currentUser *models.User) error {
	var users []models.User
	if err := db.Where("system_user = ?", false).Find(&users).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Database Error", Body: []string{"Unable to fetch users."}},
			},
		})
		return err
	}

	if !currentUser.CanDo(db, "accountList", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to view the account list."}},
			},
		})
		return nil
	}

	if len(users) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account List",
			BlockType: "info",
			Sections: []console.SectionContent{
				{SubTitle: "Information", Body: []string{"No accounts found."}},
			},
		})
		return nil
	}

	sections := make([]console.SectionContent, 0, len(users))
	for _, u := range users {
		var userGroups []models.UserGroup
		if err := db.Preload("Group").Where("user_id = ?", u.ID).Find(&userGroups).Error; err != nil {
			sections = append(sections, console.SectionContent{
				SubTitle: fmt.Sprintf("User: %s", u.Username),
				Body:     []string{"Unable to load groups."},
			})
			continue
		}

		userInfo := []string{
			fmt.Sprintf("Username: %s", u.Username),
			fmt.Sprintf("System Role: %s", u.Role),
			fmt.Sprintf("Created At: %s", u.CreatedAt.Format("2006-01-02 15:04:05")),
			fmt.Sprintf("Last Login: %s", u.LastLoginAt),
			fmt.Sprintf("Last Login From: %s", u.LastLoginFrom),
		}

		if len(userGroups) > 0 {
			groupLines := []string{"Groups:"}
			for _, ug := range userGroups {
				role := utils.GetRoles(ug)
				var coloredRole string
				switch role {
				case "Owner":
					coloredRole = utils.BgRedB("Owner")
				case "ACL Keeper":
					coloredRole = utils.BgYellowB("ACL Keeper")
				case "Gate Keeper":
					coloredRole = utils.BgGreenB("Gate Keeper")
				default:
					coloredRole = utils.BgBlueB("Member")
				}

				groupLines = append(groupLines, fmt.Sprintf("  - %s - %s", ug.Group.Name, coloredRole))
			}
			userInfo = append(userInfo, groupLines...)
		}

		sections = append(sections, console.SectionContent{
			SubTitle: fmt.Sprintf("User: %s", u.Username),
			Body:     userInfo,
		})
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account List",
		BlockType: "success",
		Sections:  sections,
	})

	return nil
}

// AccountInfo displays detailed information for a specific user account.
func AccountInfo(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountInfo", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to display information")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Missing required argument for -user flag. Please specify a username."}},
			},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		err := errors.New("missing required argument for -user flag. Please specify a username")
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{err.Error()}},
			},
		})
		return err
	}

	if !currentUser.CanDo(db, "accountInfo", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to view this account's information."}},
			},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"User not found."}},
			},
		})
		return err
	}
	var userGroups []models.UserGroup
	if err := db.Preload("Group").Where("user_id = ?", user.ID).Find(&userGroups).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{fmt.Sprintf("Error loading user groups: %v", err)}},
			},
		})
		return err
	}

	totpStatus := "❌ Disabled"
	if user.TOTPEnabled {
		totpStatus = "✅ Enabled"
	}
	passwordMFAStatus := "❌ Not set"
	if user.PasswordHash != "" {
		passwordMFAStatus = "✅ Set"
	}
	infoLines := []string{
		fmt.Sprintf("ID: %s", user.ID.String()),
		fmt.Sprintf("Username: %s", user.Username),
		fmt.Sprintf("System Role: %s", user.Role),
		fmt.Sprintf("MFA / TOTP: %s", totpStatus),
		fmt.Sprintf("MFA / Password: %s", passwordMFAStatus),
		fmt.Sprintf("Created At: %s", user.CreatedAt.Format("2006-01-02 15:04:05")),
		fmt.Sprintf("Last Login: %s", user.LastLoginAt),
		fmt.Sprintf("Last Login From: %s", user.LastLoginFrom),
		fmt.Sprintf("Groups:"),
	}

	if len(userGroups) == 0 {
		infoLines = append(infoLines, "	User isn't a member of any groups. 😭")
	} else {
		for _, ug := range userGroups {

			role := utils.GetRoles(ug)
			var coloredRole string
			switch role {
			case "Owner":
				coloredRole = utils.BgRedB("Owner")
			case "ACL Keeper":
				coloredRole = utils.BgYellowB("ACL Keeper")
			case "Gate Keeper":
				coloredRole = utils.BgGreenB("Gate Keeper")
			default:
				coloredRole = utils.BgBlueB("Member")
			}

			infoLines = append(infoLines, fmt.Sprintf(" - %s - %s", ug.Group.Name, coloredRole))
		}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Info",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "User Information", Body: infoLines},
		},
	})
	return nil
}

// AccountCreate creates a new user account with an SSH ingress key.
func AccountCreate(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountCreate", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to create")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountCreate --user <username>"}}},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountCreate --user <username>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountCreate", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to create an account."}}},
		})
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the complete public SSH key: ")
	pubKeyStr, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(pubKeyStr) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Key", Body: []string{"The provided SSH public key is invalid or missing."}}},
		})
		return fmt.Errorf("invalid or missing SSH key")
	}

	_, _, _, _, err = ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pubKeyStr)))
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Key Format", Body: []string{"The provided SSH public key is invalid."}}},
		})
		return fmt.Errorf("invalid SSH key: %v", err)
	}

	if err := CreateUser(db, username, pubKeyStr); err != nil {
		if strings.Contains(err.Error(), "exists") {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Create",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "User Exists", Body: []string{"The user already exists."}}},
			})
		} else {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Create",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to create user."}}},
			})
		}
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Create",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' created successfully.", username)}}},
	})

	return nil
}

// AccountModify updates the system role of a user account.
func AccountModify(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountModify", flag.ContinueOnError)
	var username, newRole string
	fs.StringVar(&username, "user", "", "Username to modify")
	fs.StringVar(&newRole, "sysrole", "", "New system role (admin or user)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountModify --user <username> --sysrole <admin|user>"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" || strings.TrimSpace(newRole) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountModify --user <username> --sysrole <admin|user>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountModify", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to modify this account."}}},
		})
		return nil
	}

	newRole = strings.ToLower(newRole)
	if newRole != "admin" && newRole != "user" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid System Role", Body: []string{"System role must be 'admin' or 'user'."}}},
		})
		return nil
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
		})
		return err
	}

	u.Role = newRole
	if err := db.Save(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to update user system role."}}},
		})
		return err
	}

	_ = system.UpdateSudoers(&u)
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Modify",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' system role updated to '%s'.", username, newRole)}}},
	})

	return nil
}

// AccountDelete removes a user account from the system.
func AccountDelete(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountDelete", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to delete")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountDelete --user <username>"}}},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountDelete --user <username>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountDelete", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete this account."}}},
		})
		return nil
	}

	if err := DeleteUser(db, username); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to delete user."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Delete",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' deleted successfully.", username)}}},
	})

	return nil
}

// AccountListIngressKeys lists all ingress SSH keys for a user.
func AccountListIngressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
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
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
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

	sections := make([]console.SectionContent, len(ingressKeys))
	for i, key := range ingressKeys {
		sections[i] = console.SectionContent{
			SubTitle: fmt.Sprintf("Key #%d", i+1),
			Body: []string{
				fmt.Sprintf("ID: %s", key.ID.String()),
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.Key),
			},
		}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Ingress Keys List",
		BlockType: "success",
		Sections:  sections,
	})

	return nil
}

// AccountListEgressKeys lists all egress SSH keys for a user.
func AccountListEgressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountListEgressKeys", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list egress keys")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountListEgressKeys --user <username>"}}},
		})
		return err
	}
	if strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountListEgressKeys --user <username>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountListEgressKeys", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view egress keys for this account."}}},
		})
		return fmt.Errorf("access denied")
	}

	var targetUser models.User
	if err := db.Where("username = ?", username).First(&targetUser).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
		})
		return err
	}

	var egressKeys []models.SelfEgressKey
	if err := db.Where("user_id = ?", targetUser.ID).Find(&egressKeys).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to fetch egress keys."}}},
		})
		return err
	}

	if len(egressKeys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"No egress keys found."}}},
		})
		return nil
	}

	sections := make([]console.SectionContent, len(egressKeys))
	for i, key := range egressKeys {
		sections[i] = console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.PubKey),
			},
		}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Egress Keys List",
		BlockType: "success",
		Sections:  sections,
	})

	return nil
}

// AccountListAccess lists all personal SSH accesses for a user.
func AccountListAccess(db *gorm.DB, currentUser *models.User, args []string) error {
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
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
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

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tUsername\tServer\tPort\tProtocol\tComment\tFrom\tExpires\tLast Used\tCreated At")
	for _, access := range accesses {
		lastUsed := "Never"
		if !access.LastConnection.IsZero() {
			lastUsed = access.LastConnection.Format("2006-01-02 15:04:05")
		}
		expiresStr := "Never"
		if access.ExpiresAt != nil {
			if access.ExpiresAt.Before(time.Now()) {
				expiresStr = "EXPIRED(" + access.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expiresStr = access.ExpiresAt.Format("2006-01-02")
			}
		}
		fromStr := access.AllowedFrom
		if fromStr == "" {
			fromStr = "*"
		}
		proto := access.Protocol
		if proto == "" {
			proto = "ssh"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			access.ID.String(),
			access.Username,
			access.Server,
			access.Port,
			proto,
			access.Comment,
			fromStr,
			expiresStr,
			lastUsed,
			access.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()
	tableOutput := buf.String()
	bodyLines := strings.Split(strings.TrimSpace(tableOutput), "\n")
	console.DisplayBlock(console.ContentBlock{
		Title:     "Access List",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Accesses", Body: bodyLines}},
	})

	return nil
}

// WhoHasAccessTo lists all users and groups that have access to a given server.
func WhoHasAccessTo(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("whoHasAccessTo", flag.ContinueOnError)
	var server string
	fs.StringVar(&server, "server", "", "Server to check access for")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: whoHasAccessTo --server <server>"}}},
		})
		return err
	}
	if strings.TrimSpace(server) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: whoHasAccessTo --server <server>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "whoHasAccessTo", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view accesses for this server."}}},
		})
		return nil
	}

	// Load all accesses and filter in Go (supports CIDR matching)
	var allSelfAccesses []models.SelfAccess
	if err := db.Preload("User", "deleted_at IS NULL").Where("deleted_at IS NULL").Find(&allSelfAccesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses."}}},
		})
		return err
	}

	var allGroupAccesses []models.GroupAccess
	if err := db.Preload("Group", "deleted_at IS NULL").Where("deleted_at IS NULL").Find(&allGroupAccesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving group accesses."}}},
		})
		return err
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', tabwriter.StripEscape)
	_, _ = fmt.Fprintln(w, "Type\tName\tUsername\tRole\tServer")
	for _, access := range allSelfAccesses {
		if !serverMatchesQuery(access.Server, server) {
			continue
		}
		if access.User.ID != uuid.Nil {
			_, _ = fmt.Fprintf(w, "User\t-\t%s\t-\t%s\n", access.User.Username, access.Server)
		}
	}

	for _, ga := range allGroupAccesses {
		if !serverMatchesQuery(ga.Server, server) {
			continue
		}
		var userGroups []models.UserGroup
		if err := db.Preload("User", "deleted_at IS NULL").
			Where("group_id = ? AND deleted_at IS NULL", ga.GroupID).
			Find(&userGroups).Error; err != nil {
			continue
		}

		for _, ug := range userGroups {
			if ug.User.ID == uuid.Nil {
				continue
			}

			role := utils.GetRoles(ug)
			var coloredRole string
			switch role {
			case "Owner":
				coloredRole = utils.BgRedB("Owner")
			case "ACL Keeper":
				coloredRole = utils.BgYellowB("ACL Keeper")
			case "Gate Keeper":
				coloredRole = utils.BgGreenB("Gate Keeper")
			default:
				coloredRole = utils.BgBlueB("Member")
			}

			_, _ = fmt.Fprintf(w, "Group\t%s\t%s\t%-12s\t%s\n",
				ga.Group.Name,
				ug.User.Username,
				coloredRole,
				ga.Server,
			)
		}
	}

	_ = w.Flush()
	tableOutput := buf.String()
	bodyLines := strings.Split(strings.TrimSpace(tableOutput), "\n")

	console.DisplayBlock(console.ContentBlock{
		Title:     "Who Has Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: fmt.Sprintf("Accesses to %s", server), Body: bodyLines}},
	})

	return nil
}

// serverMatchesQuery returns true if the stored server string matches the query.
// Supports exact match, substring match, and CIDR containment:
// - If query is an IP and storedServer is a CIDR, checks if the IP is in the CIDR.
// - If storedServer is an IP/hostname and query is a CIDR, checks if the server IP is in the CIDR.
func serverMatchesQuery(storedServer, query string) bool {
	// Exact or substring match
	if strings.Contains(storedServer, query) || strings.Contains(query, storedServer) {
		return true
	}
	queryIP := net.ParseIP(query)
	storedIP := net.ParseIP(storedServer)
	// Query is an IP, stored is a CIDR
	if queryIP != nil {
		_, storedCIDR, err := net.ParseCIDR(storedServer)
		if err == nil && storedCIDR.Contains(queryIP) {
			return true
		}
	}
	// Query is a CIDR, stored is an IP
	if storedIP != nil {
		_, queryCIDR, err := net.ParseCIDR(query)
		if err == nil && queryCIDR.Contains(storedIP) {
			return true
		}
	}
	return false
}

// AccountAddAccess adds a personal SSH access entry for a user.
func AccountAddAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountAddAccess", flag.ContinueOnError)
	var targetUser, server, username, comment, allowedFrom, protocol string
	var port int64
	var ttlDays int
	fs.StringVar(&targetUser, "user", "", "Target username")
	fs.StringVar(&server, "server", "", "SSH Server")
	fs.StringVar(&username, "username", "", "SSH Username")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.Int64Var(&port, "port", 22, "SSH Port")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	fs.StringVar(&protocol, "protocol", "ssh", "Protocol restriction: ssh (all), scpupload, scpdownload, sftp, rsync")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountAddAccess --user <username> --server <host> --username <user> --port <port> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync]"}}},
		})
		return err
	}

	if strings.TrimSpace(targetUser) == "" || strings.TrimSpace(server) == "" || strings.TrimSpace(username) == "" || port <= 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountAddAccess --user <username> --server <host> --username <user> --port <port> [--comment <comment>] [--from <CIDRs>] [--ttl <days>] [--protocol ssh|scpupload|scpdownload|sftp|rsync]"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountAddAccess", targetUser) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add personal access for this user."}}},
		})
		return nil
	}

	validProtocols := map[string]bool{"ssh": true, "scpupload": true, "scpdownload": true, "sftp": true, "rsync": true}
	if !validProtocols[protocol] {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: ssh, scpupload, scpdownload, sftp, rsync"}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", targetUser).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
		})
		return err
	}

	access := models.SelfAccess{UserID: user.ID, Server: server, Username: username, Port: port, Comment: comment, AllowedFrom: allowedFrom, Protocol: protocol}
	if ttlDays > 0 {
		t := time.Now().AddDate(0, 0, ttlDays)
		access.ExpiresAt = &t
	}
	if err := db.Create(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to create personal access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Personal access added successfully."}}},
	})

	return nil
}

// AccountDelAccess removes a personal SSH access entry by ID.
func AccountDelAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountDelAccess", flag.ContinueOnError)
	var accessID string
	fs.StringVar(&accessID, "access", "", "Access ID to remove")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountDelAccess --access <access_id>"}}},
		})
		return err
	}

	if strings.TrimSpace(accessID) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountDelAccess --access <access_id>"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountDelAccess", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete personal access."}}},
		})
		return nil
	}

	if err := db.Where("id = ?", accessID).Delete(&models.SelfAccess{}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to delete personal access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Personal access deleted successfully."}}},
	})

	return nil
}

// AccountSetPassword sets or clears a password MFA second factor for a user account (admin only).
func AccountSetPassword(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountSetPassword", flag.ContinueOnError)
	var targetUser string
	var clear bool
	fs.StringVar(&targetUser, "user", "", "Target username")
	fs.BoolVar(&clear, "clear", false, "Clear/remove password MFA for the user")
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	if err := fs.Parse(args); err != nil || targetUser == "" {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Usage", Body: []string{"accountSetPassword --user <username> [--clear]"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountSetPassword", targetUser) {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only admins can set password MFA for other users."}}},
		})
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", targetUser).First(&user).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
		})
		return err
	}

	if clear {
		if err := db.Model(&user).Update("password_hash", "").Error; err != nil {
			return fmt.Errorf("failed to clear password: %v", err)
		}
		slog.Default().Info("password mfa cleared by admin",
			slog.String("admin", currentUser.Username),
			slog.String("user", targetUser),
		)
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "success",
			Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA cleared for " + targetUser}}},
		})
		return nil
	}

	fmt.Print("Enter new password for " + targetUser + ": ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("could not read password: %v", err)
	}
	passStr := string(passBytes)
	if len(passStr) < 8 {
		console.DisplayBlock(console.ContentBlock{
			Title: "Set Account Password MFA", BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{"Password must be at least 8 characters."}}},
		})
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(passStr), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt error: %v", err)
	}
	if err := db.Model(&user).Update("password_hash", string(hash)).Error; err != nil {
		return fmt.Errorf("failed to save password: %v", err)
	}
	slog.Default().Info("password mfa set by admin",
		slog.String("admin", currentUser.Username),
		slog.String("user", targetUser),
	)
	console.DisplayBlock(console.ContentBlock{
		Title: "Set Account Password MFA", BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{"Password MFA set for " + targetUser}}},
	})
	return nil
}
