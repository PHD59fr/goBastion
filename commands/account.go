package commands

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"goBastion/utils/console"
	"os"
	"strings"
	"text/tabwriter"

	"goBastion/utils"
	"goBastion/utils/system"

	"goBastion/models"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

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

	if !currentUser.IsAdmin() {
		users = []models.User{*currentUser}
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
			fmt.Sprintf("ID: %s", u.ID),
			fmt.Sprintf("Username: %s", u.Username),
			fmt.Sprintf("Role: %s", u.Role),
			fmt.Sprintf("Created At: %s", u.CreatedAt.Format("2006-01-02 15:04:05")),
			fmt.Sprintf("Last Login: %s", u.LastLoginAt),
			fmt.Sprintf("Last Login From: %s", u.LastLoginFrom),
		}

		if len(userGroups) > 0 {
			groupLines := []string{"Groups:"}
			for _, ug := range userGroups {
				groupLines = append(groupLines, fmt.Sprintf("  - %s (%s)", ug.Group.Name, utils.GetGrades(ug)))
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
		err := errors.New("Missing required argument for -user flag. Please specify a username.")
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{err.Error()}},
			},
		})
		return err
	}
	if !currentUser.IsAdmin() && username != currentUser.Username {
		err := errors.New("You can only view your own information.")
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Info",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{err.Error()}},
			},
		})
		return err
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

	infoLines := []string{
		fmt.Sprintf("Username: %s", user.Username),
		fmt.Sprintf("Role: %s", user.Role),
		fmt.Sprintf("Created At: %s", user.CreatedAt.Format("2006-01-02 15:04:05")),
		fmt.Sprintf("Last Login: %s", user.LastLoginAt),
		fmt.Sprintf("Last Login From: %s", user.LastLoginFrom),
		fmt.Sprintf("Groups:"),
	}

	if len(userGroups) == 0 {
		infoLines = append(infoLines, "User isn't a member of any groups. :(")
	} else {
		for _, ug := range userGroups {
			infoLines = append(infoLines, fmt.Sprintf("		* %s - %s", ug.Group.Name, utils.GetGrades(ug)))
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

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to create an account."}}},
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

func AccountModify(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountModify", flag.ContinueOnError)
	var username, newRole string
	fs.StringVar(&username, "user", "", "Username to modify")
	fs.StringVar(&newRole, "role", "", "New role (admin or user)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountModify --user <username> --role <admin|user>"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" || strings.TrimSpace(newRole) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountModify --user <username> --role <admin|user>"}}},
		})
		return nil
	}

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to modify an account."}}},
		})
		return nil
	}

	newRole = strings.ToLower(newRole)
	if newRole != "admin" && newRole != "user" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Role", Body: []string{"Role must be 'admin' or 'user'."}}},
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
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to update user role."}}},
		})
		return err
	}

	_ = system.UpdateSudoers(&u)
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Modify",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' role updated to '%s'.", username, newRole)}}},
	})

	return nil
}

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

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to delete an account."}}},
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

	if !currentUser.IsAdmin() && username != currentUser.Username {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Ingress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to view another account's ingress keys."}}},
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

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Egress Keys List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to view another account's egress keys."}}},
		})
		return nil
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

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Access List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to view account accesses."}}},
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
	fmt.Fprintln(w, "ID\tUsername\tServer\tPort\tComment\tLast Used\tCreated At")
	for _, access := range accesses {
		lastUsed := "Never"
		if !access.LastConnection.IsZero() {
			lastUsed = access.LastConnection.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			access.ID.String(),
			access.Username,
			access.Server,
			access.Port,
			access.Comment,
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

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to view access to a server."}}},
		})
		return nil
	}

	var accesses []models.SelfAccess
	if err := db.Preload("User", "deleted_at IS NULL").Where("server LIKE ? AND deleted_at IS NULL", "%"+server+"%").Find(&accesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses."}}},
		})
		return err
	}

	var groupAccesses []models.GroupAccess
	if err := db.Preload("Group", "deleted_at IS NULL").Where("server LIKE ? AND deleted_at IS NULL", "%"+server+"%").Find(&groupAccesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Who Has Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"An error occurred while retrieving group accesses."}}},
		})
		return err
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Type\tName\tUsername\tGrade")

	for _, access := range accesses {
		if access.User.ID != uuid.Nil {
			fmt.Fprintf(w, "User\t%s\t%s\t-\n", access.User.Username, server)
		}
	}

	for _, ga := range groupAccesses {
		fmt.Fprintf(w, "Group\t%s\t-\t-\n", ga.Group.Name)
		var userGroups []models.UserGroup
		if err := db.Preload("User", "deleted_at IS NULL").Where("group_id = ? AND deleted_at IS NULL", ga.GroupID).Find(&userGroups).Error; err != nil {
			continue
		}
		for _, ug := range userGroups {
			if ug.User.ID != uuid.Nil {
				fmt.Fprintf(w, "-\t-\t%s\t%s\n", ug.User.Username, utils.GetGrades(ug))
			}
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

func AccountAddAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountAddAccess", flag.ContinueOnError)
	var targetUser, server, username, comment string
	var port int64
	fs.StringVar(&targetUser, "user", "", "Target username")
	fs.StringVar(&server, "server", "", "SSH Server")
	fs.StringVar(&username, "username", "", "SSH Username")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.Int64Var(&port, "port", 22, "SSH Port")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountAddAccess --user <username> --server <sshserver> --username <sshusername> --port <sshport> --comment <comment>"}}},
		})
		return err
	}

	if strings.TrimSpace(targetUser) == "" || strings.TrimSpace(server) == "" || strings.TrimSpace(username) == "" || port <= 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountAddAccess --user <username> --server <sshserver> --username <sshusername> --port <sshport> --comment <comment>"}}},
		})
		return nil
	}

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to add personal access."}}},
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

	access := models.SelfAccess{UserID: user.ID, Server: server, Username: username, Port: port, Comment: comment}
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

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You must be an admin to delete personal access."}}},
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
