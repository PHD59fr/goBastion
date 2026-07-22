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

// AddHost creates a new DatabaseHost entry.
func AddHost(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("dbAddHost", flag.ContinueOnError)
	var name string
	var host string
	var port int
	var protocol string
	var user string
	var password string
	var comment string
	fs.StringVar(&name, "name", "", "Host alias")
	fs.StringVar(&host, "host", "", "Hostname or IP address")
	fs.IntVar(&port, "port", 0, "Port number")
	fs.StringVar(&protocol, "protocol", "", "Protocol (mysql, postgres, mongo, redis)")
	fs.StringVar(&user, "user", "", "Database username")
	fs.StringVar(&password, "password", "", "Database password (will be encrypted)")
	fs.StringVar(&comment, "comment", "", "Optional comment")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Add Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: dbAddHost --name <name> --host <host> --port <port> --protocol <mysql|postgres|mongo|redis> --user <user> [--password <password>] [--comment <comment>]"}}},
		})
		return err
	}

	if strings.TrimSpace(name) == "" || strings.TrimSpace(host) == "" || strings.TrimSpace(user) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Add Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Missing Required Flags", Body: []string{"--name, --host, --port, --protocol, and --user are required."}}},
		})
		return fmt.Errorf("missing required flags")
	}

	if port <= 0 || port > 65535 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Add Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Port", Body: []string{"Port must be between 1 and 65535."}}},
		})
		return fmt.Errorf("invalid port: %d", port)
	}

	if !validation.IsValidDBProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Add Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: mysql, postgres, mongo, redis."}}},
		})
		return fmt.Errorf("invalid protocol: %s", protocol)
	}

	if !currentUser.IsAdmin() {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Add Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only administrators can add database hosts."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var existing models.DatabaseHost
	if err := db.Unscoped().Where("name = ? AND deleted_at IS NULL", name).First(&existing).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Add Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Exists", Body: []string{fmt.Sprintf("Host '%s' already exists.", name)}}},
		})
		return nil
	}

	var encryptedPassword string
	if password != "" {
		enc, err := cryptokey.Encrypt(password)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "DB Add Host",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Encryption Error", Body: []string{fmt.Sprintf("Failed to encrypt password: %s", err)}}},
			})
			return err
		}
		encryptedPassword = enc
	}

	dh := models.DatabaseHost{
		Name:     name,
		Host:     host,
		Port:     int64(port),
		Protocol: protocol,
		Username: user,
		Password: encryptedPassword,
		Comment:  comment,
	}
	if err := db.Create(&dh).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "DB Add Host",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to create database host."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "DB Add Host",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Database host '%s' created successfully.", name), fmt.Sprintf("ID: %s", dh.ID.String())}}},
	})
	return nil
}
