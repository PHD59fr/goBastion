package db

import (
	"flag"
	"fmt"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/dbConnector"
)

func Connect(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("dbConnect", flag.ContinueOnError)
	var host string
	fs.StringVar(&host, "host", "", "Database host name or alias (required)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("could not parse args: %w", err)
	}

	if host == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:    "dbConnect",
			BlockType: "error",
			Sections: []console.SectionContent{
				{Body: []string{"Usage: dbConnect --host <host-name>"}},
			},
		})
		return fmt.Errorf("usage: dbConnect --host <host-name>")
	}

	access, err := dbConnector.ResolveTarget(db, *user, host)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:    "dbConnect",
			BlockType: "error",
			Sections: []console.SectionContent{
				{Body: []string{err.Error()}},
			},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:    "dbConnect",
		BlockType: "success",
		Sections: []console.SectionContent{
			{Body: []string{
				fmt.Sprintf("Connecting to %s://%s:%d", access.Protocol, access.Host, access.Port),
				fmt.Sprintf("User: %s  Database: %s", access.Username, access.Database),
			}},
		},
	})

	if err := dbConnector.Connect(db, *user, access); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:    "dbConnect",
			BlockType: "error",
			Sections: []console.SectionContent{
				{Body: []string{err.Error()}},
			},
		})
		return err
	}
	return nil
}
