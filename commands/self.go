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
	"text/tabwriter"

	"goBastion/models"
	"goBastion/utils/console"
	"goBastion/utils/sshkey"
	"goBastion/utils/sync"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func SelfListIngressKeys(db *gorm.DB, user *models.User) {
	var keys []models.IngressKey
	db.Where("user_id = ?", user.ID).Find(&keys)
	if len(keys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Ingress Keys",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No ingress keys found."}},
			},
		})
		return
	}
	var sections []console.SectionContent
	for _, key := range keys {
		section := console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.Key),
			},
		}
		sections = append(sections, section)
	}
	block := console.ContentBlock{
		Title:     "My Ingress Keys",
		BlockType: "success",
		Sections:  sections,
	}
	console.DisplayBlock(block)
}

func SelfAddIngressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddIngressKey", flag.ContinueOnError)
	var pubKey string
	fs.StringVar(&pubKey, "key", "", "SSH public key")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfAddIngressKey --key <ssh_public_key>"}},
			},
		})
		return err
	}
	for i := 0; i < len(args); i++ {
		if args[i] == "--key" && i+1 < len(args) {
			pubKey = strings.Join(args[i+1:], " ")
			break
		}
	}
	if strings.TrimSpace(pubKey) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddIngressKey --key <ssh_public_key>"}},
			},
		})
		return nil
	}
	if err := CreateDBIngressKey(db, user, pubKey); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add ingress key. Please contact support."}},
			},
		})
		return err
	}
	if err := sync.IngressKeyFromDB(db, *user); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to sync ingress key. Please contact support."}},
			},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Ingress Key",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Ingress key added successfully."}},
		},
	})
	return nil
}

func SelfDelIngressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelIngressKey", flag.ContinueOnError)
	var keyId string
	fs.StringVar(&keyId, "id", "", "SSH public key ID")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	if err := fs.Parse(args); err != nil {
		if err.Error() == "invalid access ID format" {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Ingress Key",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Error", Body: []string{"Invalid Ingress Key ID format."}},
				},
			})
		} else {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Ingress Key",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelIngressKey --id <ssh_public_key_id>"}},
				},
			})
		}
		return err
	}
	if strings.TrimSpace(keyId) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelIngressKey --id <ssh_public_key_id>"}},
			},
		})
		return nil
	}
	_, err := uuid.Parse(keyId)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid access ID format."}},
			},
		})
		return fmt.Errorf("invalid key UUID: %v", err)
	}
	result := db.Where("id = ? AND user_id = ?", keyId, user.ID).Delete(&models.IngressKey{})
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Ingress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete ingress key. Please contact support."}},
			},
		})
		return fmt.Errorf("error deleting ingress key: %v", keyId)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Ingress Key",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Ingress key deleted."}},
		},
	})
	return nil
}

func SelfListEgressKeys(db *gorm.DB, user *models.User) error {
	var keys []models.SelfEgressKey
	result := db.Where("user_id = ?", user.ID).Find(&keys)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Egress Keys",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving keys. Please contact support."}},
			},
		})
		return result.Error
	}
	if len(keys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Egress Keys",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No Egress keys found."}},
			},
		})
		return nil
	}
	var sections []console.SectionContent
	for _, key := range keys {
		section := console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.PubKey),
			},
		}
		sections = append(sections, section)
	}
	block := console.ContentBlock{
		Title:     "My Egress Keys",
		BlockType: "success",
		Sections:  sections,
	}
	console.DisplayBlock(block)
	return nil
}

func SelfGenerateEgressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfGenerateEgressKey", flag.ContinueOnError)
	var keyType string
	var keySize int
	fs.StringVar(&keyType, "type", "ed25519", "Default: ed25519 - Key type")
	fs.IntVar(&keySize, "size", 256, "Default: 256 - Key size")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfGenerateEgressKey --type <keytype> --size <keysize>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(keyType) == "" || keySize <= 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfGenerateEgressKey --type <keytype> --size <keysize>"}},
			},
		})
		return nil
	}
	tmpDir := fmt.Sprintf("/home/%s/.tmp", user.Username)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to create temporary directory. Please contact support."}},
			},
		})
		return fmt.Errorf("error creating .tmp directory: %w", err)
	}
	tmpFile := fmt.Sprintf("%s/sshkey_%s.pem", tmpDir, uuid.New().String())
	cmd := exec.Command("ssh-keygen", "-t", keyType, "-b", strconv.Itoa(keySize), "-f", tmpFile, "-N", "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to generate SSH key. Please contact support."}},
			},
		})
		return fmt.Errorf("error generating SSH key: %v, %s", err, stderr.String())
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	privKeyStr, err := os.ReadFile(tmpFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to read private key. Please contact support."}},
			},
		})
		return fmt.Errorf("error reading private key: %v", err)
	}
	pubKeyStr, err := os.ReadFile(tmpFile + ".pub")
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to read public key. Please contact support."}},
			},
		})
		return fmt.Errorf("error reading public key: %v", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyStr)
	if err != nil || pubKey == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid SSH public key."}},
			},
		})
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
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to store key in database. Please contact support."}},
			},
		})
		return fmt.Errorf("error storing key in database: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Generate Egress Key",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Egress key generated and stored in the database."}},
		},
	})
	return nil
}

func SelfListAccesses(db *gorm.DB, user *models.User) error {
	var accesses []models.SelfAccess
	result := db.Where("user_id = ?", user.ID).Find(&accesses)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving accesses. Please contact support."}},
			},
		})
		return result.Error
	}
	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Personal Accesses",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "No Accesses Found", Body: []string{"You have not added any personal accesses."}},
			},
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
	block := console.ContentBlock{
		Title:     "My Personal Accesses",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Accesses", Body: bodyLines},
		},
	}
	console.DisplayBlock(block)
	return nil
}

func SelfAddAccess(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddAccess", flag.ContinueOnError)
	var server, username, comment string
	var port int64
	fs.StringVar(&server, "server", "", "Server name")
	fs.StringVar(&username, "username", "", "SSH username")
	fs.Int64Var(&port, "port", 22, "Port number")
	fs.StringVar(&comment, "comment", "", "Comment")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfAddAccess --server <server> --username <username> --port <port> --comment <comment>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(server) == "" || strings.TrimSpace(username) == "" || port <= 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddAccess --server <server> --username <username> --port <port> --comment <comment>"}},
			},
		})
		return nil
	}
	var existingAccess models.SelfAccess
	result := db.Where("user_id = ? AND server = ? AND username = ? AND port = ?", user.ID, server, username, port).First(&existingAccess)
	if result.Error == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Access already exists for this server with the given username and port."}},
			},
		})
		return nil
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred. Please contact support."}},
			},
		})
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
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add personal access. Please contact support."}},
			},
		})
		return fmt.Errorf("error adding personal access: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal Access",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Personal access added successfully."}},
		},
	})
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
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	err := fs.Parse(args)
	if err != nil {
		if strings.Contains(err.Error(), "invalid access ID format") {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Personal Access",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Error", Body: []string{"Invalid access ID format."}},
				},
			})
		} else {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Delete Personal Access",
				BlockType: "error",
				Sections: []console.SectionContent{
					{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelAccess --id <access_id>"}},
				},
			})
		}
		return err
	}
	if strings.TrimSpace(fs.Lookup("id").Value.String()) == "" || accessID == uuid.Nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelAccess --id <access_id>"}},
			},
		})
		return nil
	}
	var access models.SelfAccess
	result := db.Where("id = ? AND user_id = ?", accessID, user.ID).First(&access)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No such access found."}},
			},
		})
		return nil
	} else if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred. Please contact support."}},
			},
		})
		return fmt.Errorf("database error: %v", result.Error)
	}
	if err := db.Delete(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Access",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete personal access. Please contact support."}},
			},
		})
		return fmt.Errorf("error deleting personal access: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal Access",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Personal access deleted successfully."}},
		},
	})
	return nil
}

func SelfAddAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfAddAlias", flag.ContinueOnError)
	var alias, hostname string
	fs.StringVar(&alias, "alias", "", "Alias")
	fs.StringVar(&hostname, "hostname", "", "Host name")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfAddAlias --alias <alias> --hostname <host_name>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(alias) == "" || strings.TrimSpace(hostname) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfAddAlias --alias <alias> --hostname <host_name>"}},
			},
		})
		return nil
	}
	newHost := models.Aliases{
		ResolveFrom: alias,
		Host:        hostname,
		UserID:      &user.ID,
		GroupID:     nil,
	}
	if err := db.Create(&newHost).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to add alias. Please contact support."}},
			},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Personal Alias",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Alias added successfully."}},
		},
	})
	return nil
}

func SelfDelAlias(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfDelAlias", flag.ContinueOnError)
	var hostID string
	fs.StringVar(&hostID, "id", "", "Alias ID")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfDelAlias --id <alias_id>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(hostID) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfDelAlias --id <alias_id>"}},
			},
		})
		return nil
	}
	parsedID, err := uuid.Parse(hostID)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid alias ID format."}},
			},
		})
		return fmt.Errorf("invalid alias ID format: %v", err)
	}
	var host models.Aliases
	result := db.Where("id = ? AND user_id = ?", parsedID, user.ID).First(&host)
	if errors.Is(result.Error, gorm.ErrRecordNotFound) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"No alias found for the current user with the given ID."}},
			},
		})
		return nil
	} else if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred. Please contact support."}},
			},
		})
		return fmt.Errorf("database error: %v", result.Error)
	}
	if err := db.Delete(&host).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Personal Alias",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to delete alias. Please contact support."}},
			},
		})
		return fmt.Errorf("error deleting alias: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Personal Alias",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Alias deleted successfully."}},
		},
	})
	return nil
}

func SelfListAliases(db *gorm.DB, user *models.User) error {
	var hosts []models.Aliases
	result := db.Where("user_id = ?", user.ID).Find(&hosts)
	if result.Error != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Aliases",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"An error occurred while retrieving aliases. Please contact support."}},
			},
		})
		return result.Error
	}
	if len(hosts) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "My Aliases",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "No Aliases Found", Body: []string{"You have not added any aliases."}},
			},
		})
		return nil
	}
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tAlias\tHostname\tAdded At")
	for _, host := range hosts {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			host.ID.String(),
			host.ResolveFrom,
			host.Host,
			host.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()
	tableOutput := buf.String()
	bodyLines := strings.Split(strings.TrimSpace(tableOutput), "\n")
	block := console.ContentBlock{
		Title:     "My Aliases",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Aliases", Body: bodyLines},
		},
	}
	console.DisplayBlock(block)
	return nil
}
