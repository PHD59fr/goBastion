package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"

	"goBastion/utils/sshkey"
	"goBastion/utils/sync"

	"golang.org/x/crypto/ssh"

	"goBastion/models"

	"github.com/google/uuid"

	"gorm.io/gorm"
)

func SelfListIngressKeys(db *gorm.DB, user *models.User) {
	var keys []models.IngressKey
	db.Where("user_id = ?", user.ID).Find(&keys)
	if len(keys) == 0 {
		fmt.Println("No ingress keys found.")
	} else {
		fmt.Println("Ingress Keys:")
		for i, key := range keys {
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
	}
}

func SelfAddIngressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddIngressKey", flag.ContinueOnError)
	var pubKey string
	fs.StringVar(&pubKey, "key", "", "SSH public key")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	for i := 0; i < len(args); i++ {
		if args[i] == "--key" && i+1 < len(args) {
			pubKey = strings.Join(args[i+1:], " ")
			break
		}
	}

	if strings.TrimSpace(pubKey) == "" {
		fmt.Println("Usage: selfAddIngressKey --key <ssh_public_key>")
		return nil
	}

	if err := CreateDBIngressKey(db, user, pubKey); err != nil {
		return err
	}
	if err := sync.IngressKeyFromDB(db, *user); err != nil {
		return err
	}
	fmt.Println("Ingress key added successfully.")
	return nil
}

func SelfDelIngressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelIngressKey", flag.ContinueOnError)
	var keyId string
	fs.StringVar(&keyId, "id", "", "SSH public key ID")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if strings.TrimSpace(keyId) == "" {
		fmt.Println("Usage: selfDelIngressKey --id <ssh_public_key_id>")
		return nil
	}

	_, err := uuid.Parse(keyId)
	if err != nil {
		return fmt.Errorf("invalid key UUID: %v", err)
	}

	result := db.Where("id = ? AND user_id = ?", keyId, user.ID).Delete(&models.IngressKey{})
	if result.Error != nil {
		return fmt.Errorf("error deleting ingress key: %v", keyId)
	}
	fmt.Println("Ingress key deleted.")
	return nil
}

func SelfListEgressKeys(db *gorm.DB, user *models.User) error {
	var keys []models.SelfEgressKey
	result := db.Where("user_id = ?", user.ID).Find(&keys)

	if result.Error != nil {
		log.Printf("Database error: %v\n", result.Error)
		return result.Error
	}

	if len(keys) == 0 {
		fmt.Println("No Egress keys found.")
	} else {
		fmt.Println("Egress Keys:")
		for i, key := range keys {
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

func SelfGenerateEgressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfGenerateEgressKey", flag.ContinueOnError)
	var keyType string
	var keySize int
	fs.StringVar(&keyType, "type", "ed25519", "Default: ed25519 - Key type (e.g., rsa, ed25519)")
	fs.IntVar(&keySize, "size", 256, "Default: 256 - Key size (e.g., 2048)")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}
	if strings.TrimSpace(keyType) == "" || keySize <= 0 {
		fmt.Println("Usage: selfGenerateEgressKey --type <keytype> --size <keysize>")
		return nil
	}

	tmpDir := fmt.Sprintf("/home/%s/.tmp", user.Username)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return fmt.Errorf("error creating .tmp directory: %w", err)
	}

	tmpFile := fmt.Sprintf("%s/sshkey_%s.pem", tmpDir, uuid.New().String())
	cmd := exec.Command("ssh-keygen", "-t", keyType, "-b", strconv.Itoa(keySize), "-f", tmpFile, "-N", "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error generating SSH key: %v, %s", err, stderr.String())
	}

	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	privKeyStr, err := os.ReadFile(tmpFile)
	if err != nil {
		return fmt.Errorf("error reading private key: %v", err)
	}

	pubKeyStr, err := os.ReadFile(tmpFile + ".pub")
	if err != nil {
		return fmt.Errorf("error reading public key: %v", err)
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyStr)
	if err != nil || pubKey == nil {
		return fmt.Errorf("invalid SSH key: %s", err)
	}

	sha256Fingerprint := sha256.Sum256(pubKey.Marshal())
	fingerprint := base64.StdEncoding.EncodeToString(sha256Fingerprint[:])
	keySize = sshkey.GetKeySize(pubKey)

	newKey := models.SelfEgressKey{
		UserID:      user.ID,
		PubKey:      strings.TrimSpace(string(pubKeyStr)),
		PrivKey:     strings.TrimSpace(string(privKeyStr)),
		Type:        keyType,
		Size:        keySize,
		Fingerprint: fingerprint,
	}

	if err := db.Create(&newKey).Error; err != nil {
		return fmt.Errorf("error storing key in database: %v", err)
	}

	fmt.Println("Egress key generated and stored in the database.")
	return nil
}

func SelfListAccesses(db *gorm.DB, user *models.User) error {
	var accesses []models.SelfAccess
	db.Where("user_id = ?", user.ID).Find(&accesses)
	if len(accesses) == 0 {
		fmt.Println("No accesses found.")
	} else {
		fmt.Println("Personal Accesses:")
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
			fmt.Printf("  Last Used: %s\n", access.LastConnection.Format("2006-01-02 15:04:05"))
			fmt.Printf("  Created At: %s\n", access.CreatedAt.Format("2006-01-02 15:04:05"))
		}
	}
	return nil
}

func SelfAddAccess(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddAccess", flag.ContinueOnError)
	var server, username, comment string
	var port int64
	fs.StringVar(&server, "server", "", "Server name")
	fs.StringVar(&username, "username", "", "Username")
	fs.Int64Var(&port, "port", 22, "Port number")
	fs.StringVar(&comment, "comment", "", "Comment")

	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if strings.TrimSpace(server) == "" || strings.TrimSpace(username) == "" || port <= 0 {
		fmt.Println("Usage: selfAddAccess --server <server> --username <username> --port <port> --comment <comment>")
		return nil
	}

	var existingAccess models.SelfAccess
	result := db.Where("user_id = ? AND server = ? AND username = ? AND port = ?", user.ID, server, username, port).First(&existingAccess)
	if result.Error == nil {
		fmt.Println("Access already exists for this server with given username and port.")
		return nil
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		return fmt.Errorf("database error: %v", result.Error)
	}

	access := models.SelfAccess{
		UserID:   user.ID,
		Server:   server,
		Username: username,
		Port:     port,
		Comment:  comment,
	}
	if err := db.Create(&access).Error; err != nil {
		return fmt.Errorf("error adding personal access: %v", err)
	}

	fmt.Println("Personal access added successfully.")
	return nil
}

func SelfDelAccess(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelAccess", flag.ContinueOnError)
	var accessID uuid.UUID
	fs.Func("id", "Access ID", func(s string) error {
		parsedID, err := uuid.Parse(s)
		if err != nil {
			return fmt.Errorf("invalid access ID format")
		}
		accessID = parsedID
		return nil
	})
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if accessID == uuid.Nil {
		fmt.Println("Usage: selfDelAccess --id <access_id>")
		return nil
	}

	var access models.SelfAccess
	result := db.Where("id = ? AND user_id = ?", accessID, user.ID).First(&access)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		fmt.Println("No such access found.")
		return nil
	} else if result.Error != nil {
		return fmt.Errorf("database error: %v", result.Error)
	}

	if err := db.Delete(&access).Error; err != nil {
		return fmt.Errorf("error deleting personal access: %v", err)
	}

	fmt.Println("Personal access deleted successfully.")
	return nil
}

func SelfAddAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddAlias", flag.ContinueOnError)
	var alias, hostname string
	fs.StringVar(&alias, "alias", "", "Alias")
	fs.StringVar(&hostname, "hostname", "", "Host name")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if strings.TrimSpace(alias) == "" || strings.TrimSpace(hostname) == "" {
		fmt.Println("Usage: selfAddAlias --alias <alias> --hostname <host_name>")
		return nil
	}

	newHost := models.Aliases{
		ResolveFrom: alias,
		Host:        hostname,
		UserID:      &user.ID,
		GroupID:     nil,
	}

	if err := db.Create(&newHost).Error; err != nil {
		return fmt.Errorf("error adding host: %v", err)
	}

	fmt.Printf("Alias added successfully\n")
	return nil
}

func SelfDelAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelAlias", flag.ContinueOnError)
	var hostID string
	fs.StringVar(&hostID, "id", "", "Alias ID")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		return err
	}

	if strings.TrimSpace(hostID) == "" {
		fmt.Println("Usage: selfDelAlias --id <alias_id>")
		return nil
	}

	parsedID, err := uuid.Parse(hostID)
	if err != nil {
		return fmt.Errorf("invalid host ID format: %v", err)
	}

	var host models.Aliases
	result := db.Where("id = ? AND user_id = ?", parsedID, user.ID).First(&host)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		fmt.Println("No host found with the given ID for the current user.")
		return nil
	} else if result.Error != nil {
		return fmt.Errorf("database error: %v", result.Error)
	}

	if err := db.Delete(&host).Error; err != nil {
		return fmt.Errorf("error deleting host: %v", err)
	}

	fmt.Println("Alias deleted successfully\n")
	return nil
}

func SelfListAliases(db *gorm.DB, user *models.User) error {
	var hosts []models.Aliases
	result := db.Where("user_id = ?", user.ID).Find(&hosts)
	if result.Error != nil {
		return fmt.Errorf("error retrieving hosts: %v", result.Error)
	}

	if len(hosts) == 0 {
		fmt.Println("No alias found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAlias\tHostname\tAdded At")
	for _, host := range hosts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			host.ID.String(),
			host.ResolveFrom,
			host.Host,
			host.CreatedAt.Format("2006-01-02 15:04:05"))
	}
	_ = w.Flush()
	return nil
}
