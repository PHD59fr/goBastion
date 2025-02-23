package commands

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"goBastion/utils"
	"goBastion/utils/system"

	"goBastion/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func AccountList(db *gorm.DB, currentUser *models.User) {
	var users []models.User
	if err := db.Where("system_user = ?", false).Find(&users).Error; err != nil {
		fmt.Printf("Error fetching users: %v\n", err)
		return
	}

	if !currentUser.IsAdmin() {
		users = []models.User{*currentUser}
	}

	if len(users) == 0 {
		fmt.Println("No accounts found.")
		return
	}

	fmt.Printf("Accounts:\n")
	for i, u := range users {
		if i > 0 {
			fmt.Println("-------------------------")
		}
		var userGroups []models.UserGroup
		if err := db.Preload("Group").Where("user_id = ?", u.ID).Find(&userGroups).Error; err != nil {
			fmt.Printf("Error loading groups for user %s: %v\n", u.Username, err)
			continue
		}

		groupsInfo := ""
		for _, ug := range userGroups {
			groupsInfo += fmt.Sprintf("\n   %s - %s", ug.Group.Name, utils.GetGrades(ug))
		}
		if groupsInfo != "" {
			groupsInfo = fmt.Sprintf("Groups: %s", groupsInfo)
		}
		fmt.Printf("  ID: %s\n", u.ID)
		fmt.Printf("  Username: %s\n", u.Username)
		fmt.Printf("  Role: %s\n", u.Role)
		fmt.Printf("  Created At: %s\n", u.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Last Login: %s\n", u.LastLoginAt)
		fmt.Printf("  Last Login From: %s\n", u.LastLoginFrom)
		fmt.Printf("  %s\n", groupsInfo)
	}
}

func AccountInfo(db *gorm.DB, currentUser *models.User, args []string) {
	fs := flag.NewFlagSet("accountInfo", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to display information")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return
	}

	if strings.TrimSpace(username) == "" {
		fmt.Println("Usage: accountInfo --user <username>")
		return
	}

	if !currentUser.IsAdmin() && username != currentUser.Username {
		fmt.Println("Access denied: you can only view your own information.")
		username = currentUser.Username
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		fmt.Println("User not found.")
		return
	}

	var userGroups []models.UserGroup
	if err := db.Preload("Group").Where("user_id = ?", user.ID).Find(&userGroups).Error; err != nil {
		fmt.Printf("Error loading user groups: %v\n", err)
		return
	}

	groupsInfo := ""
	for _, ug := range userGroups {
		groupsInfo += fmt.Sprintf("\n   %s - %s", ug.Group.Name, utils.GetGrades(ug))
	}
	if len(userGroups) > 0 {
		groupsInfo = fmt.Sprintf("\n Groups: %s", groupsInfo)
	}

	fmt.Printf("User Information:\n")
	fmt.Printf("  Username: %s\n", user.Username)
	fmt.Printf("  Role: %s\n", user.Role)
	fmt.Printf("  Created At: %s\n", user.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Last Login: %s\n", user.LastLoginAt)
	fmt.Printf("  Last Login From: %s\n", user.LastLoginFrom)
	fmt.Printf("  Groups: %s\n", groupsInfo)
}

func AccountCreate(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountCreate", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to create")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(username) == "" {
		fmt.Println("Usage: accountCreate --user <username>")
		return nil
	}

	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to create an account.")
		return nil
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the complete public SSH key: ")
	pubKey, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading public key: %s", err)
	}

	err = CreateUser(db, username, pubKey)
	if err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}

	fmt.Printf("User '%s' created.\n", username)
	return nil
}

func AccountModify(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountModify", flag.ContinueOnError)
	var username, newRole string
	fs.StringVar(&username, "user", "", "Username to modify")
	fs.StringVar(&newRole, "role", "", "New role (admin or user)")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(username) == "" || strings.TrimSpace(newRole) == "" {
		fmt.Println("Usage: accountModify --user <username> --role <new_role>")
		return nil
	}

	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to edit an account.")
		return nil
	}

	newRole = strings.ToLower(newRole)
	if newRole != "admin" && newRole != "user" {
		fmt.Println("Role must be 'admin' or 'user'.")
		return nil
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	u.Role = newRole
	if err := db.Save(&u).Error; err != nil {
		return fmt.Errorf("error updating user role: %w", err)
	}
	_ = system.UpdateSudoers(&u)
	fmt.Printf("User '%s' role updated to '%s'.\n", username, newRole)
	return nil
}

func AccountDelete(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountDelete", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to delete")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(username) == "" {
		fmt.Println("Usage: accountDelete --user <username>")
		return nil
	}
	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to delete an account.")
		return nil
	}
	if err := DeleteUser(db, username); err != nil {
		return fmt.Errorf("error deleting user: %w", err)
	}
	fmt.Printf("User '%s' deleted.\n", username)
	return nil
}

func AccountListIngressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountListIngressKeys", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list ingress keys")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(username) == "" {
		fmt.Println("Usage: accountListIngressKeys --user <username>")
		return nil
	}

	if !currentUser.IsAdmin() && username != currentUser.Username {
		fmt.Println("Access denied: you must be an admin to view another account's ingress keys.")
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	var ingressKeys []models.IngressKey
	if err := db.Where("user_id = ?", user.ID).Find(&ingressKeys).Error; err != nil {
		return fmt.Errorf("error fetching ingress keys: %w", err)
	}
	fmt.Println("Ingress Keys:")
	for i, key := range ingressKeys {
		if i > 0 {
			fmt.Println("-------------------------")
		}
		fmt.Printf("Key #%d\n", i+1)
		fmt.Printf("  ID: %s\n", key.ID.String())
		fmt.Printf("  Type: %s\n", key.Type)
		fmt.Printf("  Fingerprint: %s\n", key.Fingerprint)
		fmt.Printf("  Size: %d\n", key.Size)
		fmt.Printf("  Last Update: %s\n", key.UpdatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("  Public Key: %s\n", key.Key)
	}
	return nil
}

func AccountListEgressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountListEgressKeys", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list egress keys")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(username) == "" {
		fmt.Println("Usage: accountListEgressKeys --user <username>")
		return nil
	}

	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to view another account's egress keys")
		return nil
	}

	var targetUser models.User
	if err := db.Where("username = ?", username).First(&targetUser).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	var egressKeys []models.SelfEgressKey
	if err := db.Where("user_id = ?", targetUser.ID).Find(&egressKeys).Error; err != nil {
		return fmt.Errorf("error fetching egress keys: %w", err)
	}

	if len(egressKeys) == 0 {
		fmt.Println("No Egress keys found.")
	} else {
		fmt.Println("Egress Keys:")
		for i, key := range egressKeys {
			if i > 0 {
				fmt.Println("-------------------------")
			}
			fmt.Printf("Key #%d\n", i+1)
			fmt.Printf("  ID: %s\n", key.ID.String())
			fmt.Printf("  Type: %s\n", key.Type)
			fmt.Printf("  Fingerprint: %s\n", key.Fingerprint)
			fmt.Printf("  Size: %d\n", key.Size)
			fmt.Printf("  Last Update: %s\n", key.UpdatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Public Key: %s\n", key.PubKey)

		}
	}

	return nil
}

func AccountListAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to view account accesses.")
		return nil
	}
	fs := flag.NewFlagSet("accountListAccess", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to list accesses")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(username) == "" {
		fmt.Println("Usage: accountListAccesses --user <username>")
		return nil
	}
	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	var accesses []models.SelfAccess
	if err := db.Where("user_id = ?", user.ID).Find(&accesses).Error; err != nil {
		return fmt.Errorf("error fetching accesses: %w", err)
	}
	if len(accesses) == 0 {
		fmt.Println("No accesses found.")
	} else {
		fmt.Println("Accesses:")
		for i, access := range accesses {
			if i > 0 {
				fmt.Println("-------------------------")
			}
			fmt.Printf("Access #%d\n", i+1)
			fmt.Printf("  ID: %s\n", access.ID)
			fmt.Printf("  Username: %s\n", access.Username)
			fmt.Printf("  Server: %s\n", access.Server)
			fmt.Printf("  Port: %d\n", access.Port)
			fmt.Printf("  Comment: %s\n", access.Comment)
			fmt.Printf("  Last Used: %s\n", access.LastConnection.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Created At: %s\n", access.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	}
	return nil
}
func WhoHasAccessTo(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("whoHasAccessTo", flag.ContinueOnError)
	var server string
	fs.StringVar(&server, "server", "", "Server to check access for")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("failed to parse flags: %v", err)
	}

	if server == "" {
		fmt.Print("Usage: whoHasAccessTo --server <server>")
		return nil
	}

	if !user.IsAdmin() {
		fmt.Print("Access denied: you must be an admin to view access to a server.")
		return nil
	}

	var accesses []models.SelfAccess
	if err := db.Preload("User", "deleted_at IS NULL").
		Where("server LIKE ? AND deleted_at IS NULL", "%"+server+"%").
		Find(&accesses).Error; err != nil {
		return fmt.Errorf("error fetching self accesses: %v", err)
	}

	for _, access := range accesses {
		if access.User.ID != uuid.Nil {
			fmt.Printf("User: %s has access to %s\n", access.User.Username, server)
		}
	}

	var groupAccesses []models.GroupAccess
	if err := db.Preload("Group", "deleted_at IS NULL").
		Where("server LIKE ? AND deleted_at IS NULL", "%"+server+"%").
		Find(&groupAccesses).Error; err != nil {
		return fmt.Errorf("error fetching group accesses: %v", err)
	}

	if len(groupAccesses) > 0 {
		for _, access := range groupAccesses {
			fmt.Printf("Group: %s has access to %s\n", access.Group.Name, server)
			var userGroups []models.UserGroup
			if err := db.Preload("User", "deleted_at IS NULL").
				Where("group_id = ? AND deleted_at IS NULL", access.GroupID).
				Find(&userGroups).Error; err != nil {
				return fmt.Errorf("error fetching user groups: %v", err)
			}
			for _, ug := range userGroups {
				if ug.User.ID != uuid.Nil {
					fmt.Printf(" - User: %s - %s\n", utils.FgYellow(ug.User.Username), utils.GetGrades(ug))
				}
			}
		}
	} else {
		fmt.Println("No group accesses found for server.")
	}

	return nil
}

func AccountAddAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to add personal access.")
		return nil
	}
	fs := flag.NewFlagSet("accountAddAccess", flag.ContinueOnError)

	var targetUser, server, username, comment string
	var port int64
	fs.StringVar(&targetUser, "user", "", "Target username")
	fs.StringVar(&server, "server", "", "SSH Server")
	fs.StringVar(&username, "username", "", "SSH Username")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.Int64Var(&port, "port", 22, "SSH Port")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if strings.TrimSpace(server) == "" || strings.TrimSpace(username) == "" || port <= 0 {
		fmt.Println("Usage: accountAddAccess --user <username> --server <sshserver> --username <sshusername> --port <sshport> --comment <comment>")
		return nil
	}

	var user models.User
	if err := db.Where("username = ?", targetUser).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	access := models.SelfAccess{UserID: user.ID, Server: server, Username: username, Port: port, Comment: comment}
	if err := db.Create(&access).Error; err != nil {
		return fmt.Errorf("error creating personal access: %w", err)
	}
	fmt.Println("Personal access added for account.")
	return nil
}

func AccountDelAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to delete personal access.")
		return nil
	}
	fs := flag.NewFlagSet("accountDelAccess", flag.ContinueOnError)
	var accessID string
	fs.StringVar(&accessID, "access", "", "Access ID to remove")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(accessID) == "" {
		fmt.Println("Usage: accountDelAccess --access <access_id>")
		return nil
	}
	if err := db.Where("id = ?", accessID).Delete(&models.SelfAccess{}).Error; err != nil {
		return fmt.Errorf("error deleting personal access: %w", err)
	}
	fmt.Println("Personal access deleted for account.")
	return nil
}
