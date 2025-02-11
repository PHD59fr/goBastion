package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"goBastion/utils"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"goBastion/models"
	"goBastion/utils/sshkey"

	"gorm.io/gorm"
)

func GroupInfo(db *gorm.DB, args []string) error {
	fs := flag.NewFlagSet("groupInfo", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(groupName) == "" {
		fmt.Println("Usage: groupInfo --group <groupName>")
		return nil
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		fmt.Println("Group not found.")
		return nil
	}

	fmt.Printf("Group ID: %s, Name: %s\n", g.ID.String(), g.Name)
	var userGroups []models.UserGroup
	if err := db.Preload("User").Where("group_id = ?", g.ID).Find(&userGroups).Error; err != nil {
		return fmt.Errorf("error retrieving group members: %v", err)
	}
	if len(userGroups) == 0 {
		fmt.Println("No members in this group.")
	} else {
		fmt.Println("Group Users:")
		for _, ug := range userGroups {
			fmt.Printf(" * %s - %s\n", ug.User.Username, utils.GetGrades(ug))
		}
	}

	var egressKeys []models.GroupEgressKey
	if err := db.Where("group_id = ?", g.ID).Find(&egressKeys).Error; err != nil {
		fmt.Printf("Error retrieving group egress keys: %v\n", err)
	} else {
		if len(egressKeys) > 0 {
			fmt.Println("Group Egress Public Keys:")
			for _, key := range egressKeys {
				fmt.Printf("%s\n", key.PubKey)
			}
		} else {
			fmt.Println("No group egress keys found.")
		}
	}

	return nil
}

func GroupList(db *gorm.DB, user *models.User, args []string) {
	fs := flag.NewFlagSet("groupList", flag.ContinueOnError)
	all := fs.Bool("all", false, "List all groups")
	_ = fs.Parse(args)
	if *all {
		var groups []models.Group
		db.Unscoped().Find(&groups)
		if len(groups) == 0 {
			fmt.Println("No groups found.")
			return
		}
		fmt.Println("Groups:")
		for i, g := range groups {
			if i > 0 {
				fmt.Println("-------------------------")
			}
			fmt.Printf("Group #%d\n", i+1)
			fmt.Printf("  ID: %s\n", g.ID.String())
			fmt.Printf("  Name: %s\n", g.Name)
		}
		return
	} else {
		var userGroups []models.UserGroup
		db.Preload("Group").Where("user_id = ?", user.ID).Find(&userGroups)
		if len(userGroups) == 0 {
			fmt.Println("No groups found.")
			return
		}
		fmt.Println("Your Groups:")
		for i, ug := range userGroups {
			if i > 0 {
				fmt.Println("-------------------------")
			}
			fmt.Printf("Group #%d\n", i+1)
			fmt.Printf("  ID: %s\n", ug.Group.ID.String())
			fmt.Printf("  Name: %s\n", ug.Group.Name)
		}
	}
}

func GroupCreate(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupCreate", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(groupName) == "" {
		fmt.Println("Usage: groupCreate --group <groupName>")
		return nil
	}

	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to create groups.")
		return nil
	}

	var existingGroup models.Group
	if err := db.Unscoped().Where("name = ? AND deleted_at IS NULL", groupName).First(&existingGroup).Error; err == nil {
		fmt.Printf("Group '%s' already exists.\n", groupName)
		return nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("error checking group existence: %v", err)
	}
	g := models.Group{Name: groupName}
	if err := db.Create(&g).Error; err != nil {
		return fmt.Errorf("error creating group: %v", err)
	}

	fmt.Printf("Group '%s' created successfully.\n", groupName)
	return nil
}

func GroupDelete(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelete", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(groupName) == "" {
		fmt.Println("Usage: groupDelete --group <groupName>")
		return nil
	}
	if !currentUser.IsAdmin() {
		fmt.Println("Access denied: you must be an admin to delete groups.")
		return nil
	}

	db.Where("name = ?", groupName).Delete(&models.Group{})
	fmt.Printf("Group '%s' deleted.\n", groupName)
	return nil
}

func GroupAddMember(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddMember", flag.ContinueOnError)
	var groupName, username, grade string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&username, "user", "", "Username to add")
	fs.StringVar(&grade, "grade", "", "Grade (owner, aclkeeper, gatekeeper, member, guest)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(groupName) == "" || strings.TrimSpace(username) == "" || strings.TrimSpace(grade) == "" {
		fmt.Println("Usage: groupAddMember --group <groupName> --user <username> --grade <grade>")
		return nil
	}

	grade = strings.TrimSpace(strings.ToLower(grade))
	if !utils.CheckGrade(grade) {
		return fmt.Errorf("invalid grade: %s", grade)
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		return fmt.Errorf("group not found: %s", groupName)
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		return fmt.Errorf("user not found: %s", username)
	}

	var ug models.UserGroup
	if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).First(&ug).Error; err == nil {
		return fmt.Errorf("User '%s' is already in this group '%s'. No changes made.\n", username, groupName)
	}

	right := false
	var myGroups []models.UserGroup
	db.Where("user_id = ?", currentUser.ID).Find(&myGroups)
	for _, myGroup := range myGroups {
		if myGroup.GroupID == g.ID {
			right = true
			break
		}
	}

	if right {
		var myUserGroup models.UserGroup
		db.Where("user_id = ? AND group_id = ?", currentUser.ID, g.ID).First(&myUserGroup)
		if !myUserGroup.IsOwner() {
			if grade == "owner" || grade == "aclkeeper" {
				fmt.Println("Access denied: you cannot add an owner to a group.")
				return nil
			}
			if grade == "gatekeeper" && !myUserGroup.IsACLKeeper() {
				fmt.Println("Access denied: you must be an ACLKeeper to add a gatekeeper.")
				return nil
			}
			if grade == "member" || grade == "guest" {
				if !myUserGroup.IsGateKeeper() && !myUserGroup.IsACLKeeper() {
					fmt.Println("Access denied: you must be an ACLKeeper or a GateKeeper to add a member or guest.")
					return nil
				}
			}
		}
	}

	if currentUser.IsAdmin() {
		right = true
	}

	if !right {
		fmt.Println("Access denied: you must be an admin or a member of the group to add users.")
		return nil
	}

	newUG := models.UserGroup{
		UserID:  u.ID,
		GroupID: g.ID,
		Role:    grade,
	}
	db.Create(&newUG)
	fmt.Printf("User '%s' added to group '%s' as '%s'.\n", username, groupName, grade)

	return nil
}

func GroupDelMember(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelMember", flag.ContinueOnError)
	var groupName, username string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&username, "user", "", "Username to remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(groupName) == "" || strings.TrimSpace(username) == "" {
		fmt.Println("Usage: groupDelMember --group <groupName> --user <username>")
		return nil
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		fmt.Println("Group not found.")
		return nil
	}
	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		fmt.Println("User not found.")
		return nil
	}

	var ug models.UserGroup
	if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).First(&ug).Error; err != nil {
		fmt.Printf("User '%s' is not in this group '%s'. No changes made.\n", username, groupName)
		return nil
	}

	if !currentUser.IsAdmin() {
		var myUserGroup models.UserGroup
		db.Where("user_id = ? AND group_id = ?", currentUser.ID, g.ID).First(&myUserGroup)

		if !myUserGroup.IsOwner() {
			if myUserGroup.IsMember() || myUserGroup.IsGuest() {
				fmt.Println("Access denied: you must be an admin, an acl-keeper or a gate-keeper of the group to remove users.")
				return nil
			}
			if myUserGroup.IsGateKeeper() && ug.IsACLKeeper() {
				fmt.Println("Access denied: you must be an acl-keeper to remove a gate-keeper.")
				return nil
			}
			if (myUserGroup.IsACLKeeper() || myUserGroup.IsGateKeeper()) && ug.IsOwner() {
				fmt.Println("Access denied: you must be an owner to remove an acl-keeper/gate-keeper.")
				return nil
			}
		}
	}
	db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).Delete(&models.UserGroup{})
	fmt.Printf("User '%s' removed from group '%s'.\n", username, groupName)
	return nil
}

func GroupGenerateEgressKey(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupGenerateEgressKey", flag.ContinueOnError)
	var groupName string
	var keyType string
	var keySize int

	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&keyType, "type", "ed25519", "Default: ed25519 - Key type (e.g., rsa, ed25519)")
	fs.IntVar(&keySize, "size", 256, "Default: 256 - Key size (e.g., 2048)")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if strings.TrimSpace(groupName) == "" {
		fmt.Println("Usage: groupGenerateEgressKey --group <groupName> --type <keyType> --size <keySize>")
		return nil
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		return fmt.Errorf("group not found: %s", groupName)
	}
	if !currentUser.IsAdmin() {
		var userGroup models.UserGroup
		if err := db.Where("user_id = ? AND group_id = ?", currentUser.ID, group.ID).First(&userGroup).Error; err != nil {
			return fmt.Errorf("access denied: you are not a member of group %s", groupName)
		}
		if !(userGroup.IsOwner() || userGroup.IsACLKeeper() || userGroup.IsGateKeeper()) {
			return fmt.Errorf("access denied: insufficient privileges to generate group egress key")
		}
	}

	tmpDir := fmt.Sprintf("/home/%s/.tmp", currentUser.Username)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return fmt.Errorf("error creating temporary directory: %v", err)
	}
	tmpFile := fmt.Sprintf("%s/sshkey_%s.pem", tmpDir, uuid.New().String())
	hostname, _ := os.Hostname()
	cmd := exec.Command("ssh-keygen", "-t", keyType, "-b", strconv.Itoa(keySize), "-C", groupName+"@"+hostname+":GROUP", "-f", tmpFile, "-N", "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error generating SSH key: %v, %s", err, stderr.String())
	}
	privKeyBytes, err := os.ReadFile(tmpFile)
	if err != nil {
		return fmt.Errorf("error reading private key: %v", err)
	}
	pubKeyBytes, err := os.ReadFile(tmpFile + ".pub")
	if err != nil {
		return fmt.Errorf("error reading public key: %v", err)
	}
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
	if err != nil || parsedKey == nil {
		return fmt.Errorf("invalid SSH key: %v", err)
	}
	sha256Fingerprint := sha256.Sum256(parsedKey.Marshal())
	fingerprint := base64.StdEncoding.EncodeToString(sha256Fingerprint[:])
	keySize = sshkey.GetKeySize(parsedKey)
	_ = os.RemoveAll(tmpDir)
	newKey := models.GroupEgressKey{
		GroupID:     group.ID,
		PubKey:      strings.TrimSpace(string(pubKeyBytes)),
		PrivKey:     strings.TrimSpace(string(privKeyBytes)),
		Type:        keyType,
		Size:        keySize,
		Fingerprint: fingerprint,
	}
	if err = db.Create(&newKey).Error; err != nil {
		return fmt.Errorf("error storing group egress key in database: %v", err)
	}
	fmt.Printf("Group egress key generated and stored for group '%s'.\n", groupName)
	return nil
}

func GroupListEgressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListEgressKeys", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(groupName) == "" {
		fmt.Println("Usage: groupListEgressKeys --group <groupName>")
		return nil
	}
	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		return fmt.Errorf("group not found: %s", groupName)
	}
	if !currentUser.IsAdmin() {
		var userGroup models.UserGroup
		if err := db.Where("user_id = ? AND group_id = ?", currentUser.ID, group.ID).First(&userGroup).Error; err != nil {
			return fmt.Errorf("access denied: you are not a member of group %s", groupName)
		}
		if !(userGroup.IsOwner() || userGroup.IsACLKeeper() || userGroup.IsGateKeeper()) {
			return fmt.Errorf("access denied: insufficient privileges to list group egress keys")
		}
	}
	var keys []models.GroupEgressKey
	if err := db.Where("group_id = ?", group.ID).Find(&keys).Error; err != nil {
		return fmt.Errorf("error fetching group egress keys: %v", err)
	}
	if len(keys) == 0 {
		fmt.Printf("No egress keys found for group '%s'.\n", groupName)
	} else {
		fmt.Printf("Egress Keys for group '%s':\n", groupName)
		for i, key := range keys {
			if i > 0 {
				fmt.Println("-------------------------")
			}
			fmt.Printf("Key #%d\n", i+1)
			fmt.Printf("  ID: %s\n", key.ID.String())
			fmt.Printf("  Type: %s\n", key.Type)
			fmt.Printf("  Fingerprint: %s\n", key.Fingerprint)
			fmt.Printf("  Size: %d\n", key.Size)
			fmt.Printf("  Created At: %s\n", key.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Public Key: %s\n", key.PubKey)
		}
	}
	return nil
}

func GroupAddAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddAccess", flag.ContinueOnError)
	var groupName, server, username, comment string
	var port int64
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&server, "server", "", "Server to add access for")
	fs.Int64Var(&port, "port", 22, "Port number")
	fs.StringVar(&username, "username", "", "Connection username")
	fs.StringVar(&comment, "comment", "", "Comment")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if groupName == "" || server == "" || username == "" {
		fmt.Println("Usage: groupAddAccess --group <groupName> --server <server> --port <port> --username <connection username> --comment <comment>")
		return nil
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		return fmt.Errorf("group not found: %s", groupName)
	}

	if err := checkGroupPrivileges(db, currentUser, group.ID); err != nil {
		return err
	}

	var existingAccess models.GroupAccess
	if err := db.Where("group_id = ? AND server = ? AND port = ? AND username = ?", group.ID, server, port, username).First(&existingAccess).Error; err == nil {
		fmt.Println("Access already exists for this group with the given server, port and connection username.")
		return nil
	}

	access := models.GroupAccess{
		GroupID:  group.ID,
		Server:   server,
		Port:     port,
		Username: username,
		Comment:  comment,
	}
	if err := db.Create(&access).Error; err != nil {
		return fmt.Errorf("error creating group access: %v", err)
	}
	fmt.Printf("Group access added for group '%s'.\n", groupName)
	return nil
}

func GroupDelAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelAccess", flag.ContinueOnError)
	var groupName, accessIDStr string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&accessIDStr, "access", "", "Access ID to remove")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if groupName == "" || accessIDStr == "" {
		fmt.Println("Usage: groupDelAccess --group <groupName> --access <access_id>")
		return nil
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		return fmt.Errorf("group not found: %s", groupName)
	}

	accessID, err := uuid.Parse(accessIDStr)
	if err != nil {
		return fmt.Errorf("invalid access ID: %v", err)
	}

	if err = checkGroupPrivileges(db, currentUser, group.ID); err != nil {
		return err
	}

	if err = db.Where("id = ? AND group_id = ?", accessID, group.ID).Delete(&models.GroupAccess{}).Error; err != nil {
		return fmt.Errorf("error deleting group access: %v", err)
	}
	fmt.Printf("Group access removed for group '%s'.\n", groupName)
	return nil
}

func GroupListAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListAccess", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(groupName) == "" {
		fmt.Println("Usage: groupListAccess --group <groupName>")
		return nil
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		fmt.Println("Group not found.")
		return nil
	}

	if !currentUser.IsAdmin() {
		var userGroup models.UserGroup
		if err := db.Where("user_id = ? AND group_id = ?", currentUser.ID, group.ID).First(&userGroup).Error; err != nil {
			fmt.Println("Access denied: you are not a member of this group.")
			return nil
		}
	}

	var accesses []models.GroupAccess
	if err := db.Where("group_id = ?", group.ID).Find(&accesses).Error; err != nil {
		fmt.Printf("Error fetching group accesses: %v\n", err)
		return err
	}

	if len(accesses) == 0 {
		fmt.Println("No accesses found for this group.")
	} else {
		fmt.Printf("Accesses for Group '%s':\n", groupName)
		for i, access := range accesses {
			if i > 0 {
				fmt.Println("-------------------------")
			}
			fmt.Printf("Access #%d\n", i+1)
			fmt.Printf("  ID: %s\n", access.ID.String())
			fmt.Printf("  Username: %s\n", access.Username)
			fmt.Printf("  Server: %s\n", access.Server)
			fmt.Printf("  Port: %d\n", access.Port)
			fmt.Printf("  Comment: %s\n", access.Comment)
			if access.LastConnection.IsZero() {
				fmt.Printf("  Last Used: Never\n")
			} else {
				fmt.Printf("  Last Used: %s\n", access.LastConnection.Format("2006-01-02 15:04:05"))
			}
			fmt.Printf("  Created At: %s\n", access.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	}
	return nil
}

func checkGroupPrivileges(db *gorm.DB, currentUser *models.User, groupID uuid.UUID) error {
	if currentUser.IsAdmin() {
		return nil
	}
	var userGroup models.UserGroup
	if err := db.Where("user_id = ? AND group_id = ?", currentUser.ID, groupID).First(&userGroup).Error; err != nil {
		return fmt.Errorf("access denied: you are not a member of the group")
	}
	if !(userGroup.IsOwner() || userGroup.IsACLKeeper() || userGroup.IsGateKeeper()) {
		return fmt.Errorf("access denied: insufficient privileges")
	}
	return nil
}
