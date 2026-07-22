package db

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// ModifyHost updates an existing DatabaseHost. Only provided flags are changed.
func ModifyHost(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("dbModifyHost", flag.ContinueOnError)
	var name string
	var host string
	var port int
	var protocol string
	var user string
	var password string
	var comment string
	var portChanged bool
	fs.StringVar(&name, "name", "", "Host alias (required)")
	fs.StringVar(&host, "host", "", "New hostname or IP address")
	fs.IntVar(&port, "port", 0, "New port number")
	fs.StringVar(&protocol, "protocol", "", "New protocol (mysql, postgres, mongo, redis)")
	fs.StringVar(&user, "user", "", "New database username")
	fs.StringVar(&password, "password", "", "New database password (will be encrypted)")
	fs.StringVar(&comment, "comment", "", "New comment")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Modify Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: dbModifyHost --name <name> [--host <host>] [--port <port>] [--protocol <protocol>] [--user <user>] [--password <password>] [--comment <comment>]"}}},
		})
		return err
	}

	if strings.TrimSpace(name) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Modify Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Missing Required Flag", Body: []string{"--name is required."}}},
		})
		return fmt.Errorf("missing required flag")
	}

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Modify Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only administrators can modify database hosts."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	fs.Visit(func(f *flag.Flag) {
		if f.Name == "port" {
			portChanged = true
		}
	})

	var dh models.DatabaseHost
	if err := db.Where("name = ? AND deleted_at IS NULL", name).First(&dh).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Modify Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Database host '%s' not found.", name)}}},
		})
		return fmt.Errorf("database host not found: %s", name)
	}

	updates := map[string]interface{}{}

	if strings.TrimSpace(host) != "" {
		updates["host"] = host
	}

	if portChanged {
		if port <= 0 || port > 65535 {
			console.DisplayBlock(console.ContentBlock{
				Title:     "DB Modify Host",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid Port", Body: []string{"Port must be between 1 and 65535."}}},
			})
			return fmt.Errorf("invalid port: %d", port)
		}
		updates["port"] = int64(port)
	}

	if strings.TrimSpace(protocol) != "" {
		if !validation.IsValidDBProtocol(protocol) {
			console.DisplayBlock(console.ContentBlock{
				Title:     "DB Modify Host",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: mysql, postgres, mongo, redis."}}},
			})
			return fmt.Errorf("invalid protocol: %s", protocol)
		}
		updates["protocol"] = protocol
	}

	if strings.TrimSpace(user) != "" {
		updates["username"] = user
	}

	if password != "" {
		enc, err := cryptokey.Encrypt(password)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "DB Modify Host",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Encryption Error", Body: []string{fmt.Sprintf("Failed to encrypt password: %s", err)}}},
			})
			return err
		}
		updates["password"] = enc
	}

	// Only set comment if the flag was explicitly provided.
	setComment := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "comment" {
			setComment = true
		}
	})
	if setComment {
		updates["comment"] = comment
	}

	if len(updates) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Modify Host",
			BlockType: "warning",
			Sections:  []console.SectionContent{{SubTitle: "No Changes", Body: []string{"No fields to update."}}},
		})
		return nil
	}

	if err := db.Model(&dh).Updates(updates).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Modify Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to update database host."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "DB Modify Host",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Database host '%s' updated successfully.", name)}}},
	})
	return nil
}
