package commands

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"goBastion/models"
	"goBastion/utils"
	"goBastion/utils/sshConnector"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func SSHConnect(db *gorm.DB, user models.User, logger slog.Logger, params string) error {
	sshUser, sshHost, sshPort, err := parseSSHCommand(params)
	if err != nil {
		return fmt.Errorf("invalid SSH command: %v", err)
	}

	sshFrom := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]
	hostname, _ := os.Hostname()

	forcedHost, err := resolveForcedHost(db, user, sshHost)
	if err != nil {
		return fmt.Errorf("error searching host: %v", err)
	}

	loginHostname := user.Username + "@" + hostname
	fmt.Printf("⚡ %s → %s → %s ...\n\n", utils.FgBlueB(sshFrom), loginHostname, utils.FgYellow(sshUser+"@"+sshHost+":"+sshPort))

	if forcedHost.Host != "" {
		sshHost = forcedHost.Host
	}

	accesses, err := accessFilter(db, user, sshUser, sshHost, sshPort)
	if err != nil {
		return fmt.Errorf("%v\n", err)
	}

	if len(accesses) > 0 {
		fmt.Printf("Trying keys ...\n")
		for _, access := range accesses {
			if access.KeyId == uuid.Nil {
				fmt.Printf("- " + access.Source + " - Skip empty egress key.\n")
				continue
			}
			fmt.Printf("- "+utils.BgGreenB("%s")+" - ID: %s "+utils.FgBlueB("%s-%d")+" [%s]...\n", access.Source, access.KeyId.String(), strings.ToUpper(access.KeyType), access.KeySize, access.KeyUpdatedAt.Format("2006-01-02"))
			err = sshConnector.SshConnection(user, access)

			if access.Type == "self" {
				db.Model(&models.SelfAccess{}).Where("id = ?", access.ID).Update("last_connection", time.Now())
			} else {
				db.Model(&models.GroupAccess{}).Where("id = ?", access.ID).Update("last_connection", time.Now())
			}

			if err != nil {
				fmt.Printf("Key verification failed: %v\n", err)
			} else {
				return nil
			}
		}
	}

	fmt.Println("No valid key found for the user or group.")
	return nil
}

func accessFilter(DB *gorm.DB, user models.User, username, host, port string) ([]models.AccessRight, error) {
	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid port value: %v", err)
	}

	var selfAccessList []models.SelfAccess
	var groupAccessList []models.GroupAccess

	// ADMIN LOGIC
	if user.Role == models.RoleAdmin {
		if err = DB.Where("username = ? AND server = ? AND port = ?", username, host, portInt).
			Find(&selfAccessList).Error; err != nil {
			return nil, fmt.Errorf("error retrieving self access for admin: %v", err)
		}
		if err = DB.Where("username = ? AND server = ? AND port = ?", username, host, portInt).
			Preload("Group").
			Find(&groupAccessList).Error; err != nil {
			return nil, fmt.Errorf("error retrieving group access for admin: %v", err)
		}

		if len(groupAccessList) > 0 {
			ga := groupAccessList[0]
			var groupEgressKey models.GroupEgressKey
			if err = DB.Where("group_id = ?", ga.GroupID).
				First(&groupEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("error retrieving group egress key for group %v: %v", ga.GroupID, err)
			}
			access := models.AccessRight{
				Source:         "admin-group-" + ga.Group.Name,
				ID:             ga.ID,
				Username:       ga.Username,
				Server:         ga.Server,
				Port:           ga.Port,
				Type:           "group",
				KeyId:          groupEgressKey.ID,
				KeyType:        groupEgressKey.Type,
				KeySize:        groupEgressKey.Size,
				KeyFingerprint: groupEgressKey.Fingerprint,
				KeyUpdatedAt:   groupEgressKey.UpdatedAt,
				PublicKey:      groupEgressKey.PubKey,
				PrivateKey:     groupEgressKey.PrivKey,
			}
			return []models.AccessRight{access}, nil
		} else if len(selfAccessList) > 0 {
			sa := selfAccessList[0]
			var selfEgressKey models.SelfEgressKey
			if err = DB.Where("user_id = ?", sa.UserID).
				First(&selfEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("error retrieving self egress key for user %v: %v", sa.UserID, err)
			}
			access := models.AccessRight{
				ID:             sa.ID,
				Source:         "admin-account-" + sa.Username,
				Username:       sa.Username,
				Server:         sa.Server,
				Port:           sa.Port,
				Type:           "self",
				KeyId:          selfEgressKey.ID,
				KeyType:        selfEgressKey.Type,
				KeySize:        selfEgressKey.Size,
				KeyFingerprint: selfEgressKey.Fingerprint,
				KeyUpdatedAt:   selfEgressKey.UpdatedAt,
				PublicKey:      selfEgressKey.PubKey,
				PrivateKey:     selfEgressKey.PrivKey,
			}
			return []models.AccessRight{access}, nil
		} else {
			return nil, errors.New("⛔ " + utils.BgRedB("Access denied for "+user.Username+" to "+username+"@"+host+":"+port))
		}
	}

	// USER LOGIC
	if err = DB.Where("user_id = ? AND username = ? AND server = ? AND port = ?", user.ID, username, host, portInt).
		Find(&selfAccessList).Error; err != nil {
		return nil, fmt.Errorf("error retrieving self access: %v", err)
	}

	var userGroups []models.UserGroup
	if err = DB.Where("user_id = ?", user.ID).
		Preload("Group").
		Find(&userGroups).Error; err != nil {
		return nil, fmt.Errorf("error retrieving user groups: %v", err)
	}

	groupIDs := make([]uuid.UUID, 0, len(userGroups))
	for _, ug := range userGroups {
		groupIDs = append(groupIDs, ug.GroupID)
	}

	if len(groupIDs) > 0 {
		if err = DB.Where("group_id IN ? AND username = ? AND server = ? AND port = ?", groupIDs, username, host, portInt).
			Preload("Group").
			Find(&groupAccessList).Error; err != nil {
			return nil, fmt.Errorf("error retrieving group access: %v", err)
		}
	}

	if len(groupAccessList) > 0 {
		ga := groupAccessList[0]
		var groupEgressKey models.GroupEgressKey
		if err = DB.Where("group_id = ?", ga.GroupID).
			First(&groupEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("error retrieving group egress key for group %v: %v", ga.GroupID, err)
		}
		access := models.AccessRight{
			ID:             ga.ID,
			Source:         "group-" + ga.Group.Name,
			Username:       ga.Username,
			Server:         ga.Server,
			Port:           ga.Port,
			Type:           "group",
			KeyId:          groupEgressKey.ID,
			KeyType:        groupEgressKey.Type,
			KeySize:        groupEgressKey.Size,
			KeyFingerprint: groupEgressKey.Fingerprint,
			KeyUpdatedAt:   groupEgressKey.UpdatedAt,
			PublicKey:      groupEgressKey.PubKey,
			PrivateKey:     groupEgressKey.PrivKey,
		}
		return []models.AccessRight{access}, nil
	} else if len(selfAccessList) > 0 {
		sa := selfAccessList[0]
		var selfEgressKey models.SelfEgressKey
		if err = DB.Where("user_id = ?", sa.UserID).
			First(&selfEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("error retrieving self egress key for user %v: %v", sa.UserID, err)
		}
		access := models.AccessRight{
			ID:             sa.ID,
			Source:         "account-" + sa.Username,
			Username:       sa.Username,
			Server:         sa.Server,
			Port:           sa.Port,
			Type:           "self",
			KeyId:          selfEgressKey.ID,
			KeyType:        selfEgressKey.Type,
			KeySize:        selfEgressKey.Size,
			KeyFingerprint: selfEgressKey.Fingerprint,
			KeyUpdatedAt:   selfEgressKey.UpdatedAt,
			PublicKey:      selfEgressKey.PubKey,
			PrivateKey:     selfEgressKey.PrivKey,
		}
		return []models.AccessRight{access}, nil
	} else {
		return nil, errors.New("⛔ " + utils.BgRedB("Access denied for "+user.Username+" to "+username+"@"+host+":"+port))
	}
}

func parseSSHCommand(command string) (user, host, port string, err error) {
	command = strings.TrimSpace(command)

	reWithPortOption := regexp.MustCompile(`^((?P<user>[^@]+)@)?(?P<host>[^\s]+)\s+-p\s*(?P<port>\d+)$`)
	match := reWithPortOption.FindStringSubmatch(command)
	if match != nil {
		user = match[2]
		host = match[3]
		port = match[4]
		if port == "" {
			port = "22"
		}
		if user == "" {
			user = "root"
		}
		return user, host, port, nil
	}

	reStandard := regexp.MustCompile(`^((?P<user>[^@]+)@)?(?P<host>[^:]+)(:(?P<port>\d+))?$`)
	match = reStandard.FindStringSubmatch(command)
	if match != nil {
		user = match[2]
		host = match[3]
		port = match[5]
		if port == "" {
			port = "22"
		}
		if user == "" {
			user = "root"
		}
		return user, host, port, nil
	}
	return "", "", "", errors.New("invalid format")
}

func resolveForcedHost(db *gorm.DB, user models.User, forcedHostname string) (models.Aliases, error) {
	host := models.Aliases{}

	err := db.
		Where("LOWER(resolve_from) = ? AND user_id = ?", strings.ToLower(forcedHostname), user.ID).
		First(&host).Error
	if err == nil {
		return host, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return host, fmt.Errorf("error retrieving user host: %v", err)
	}

	var groupIDs []uuid.UUID
	err = db.Model(&models.UserGroup{}).
		Where("user_id = ?", user.ID).
		Pluck("group_id", &groupIDs).Error
	if err != nil {
		return host, fmt.Errorf("error retrieving user groups: %v", err)
	}

	if len(groupIDs) == 0 {
		return host, nil
	}

	err = db.
		Where("LOWER(resolve_from) = ? AND group_id IN (?)", strings.ToLower(forcedHostname), groupIDs).
		First(&host).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return host, nil
	} else if err != nil {
		return host, fmt.Errorf("error retrieving group host: %v", err)
	}

	return host, nil
}
