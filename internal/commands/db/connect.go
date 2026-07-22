package db

import (
	"flag"
	"fmt"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/dbConnector"
)

// Connect resolves the target and establishes a database connection through the bastion.
func Connect(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("dbConnect", flag.ContinueOnError)
	var host string
	fs.StringVar(&host, "host", "", "Database host, host:port, host:port:protocol, or alias (required)")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Connect to Database",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Usage: dbConnect --host <host>"}},
			},
		})
		return err
	}

	if host == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Connect to Database",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"Usage: dbConnect --host <host>"}},
			},
		})
		return fmt.Errorf("missing required argument: --host")
	}

	access, err := dbConnector.ResolveTarget(db, *user, host, args...)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Connect to Database",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{err.Error()}},
			},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Connect to Database",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Connecting", Body: []string{
				fmt.Sprintf("Connecting to %s://%s:%d", access.Protocol, access.Host, access.Port),
				fmt.Sprintf("User: %s  Database: %s", access.Username, access.Database),
			}},
		},
	})

	if err := dbConnector.Connect(db, *user, access); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Connect to Database",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{err.Error()}},
			},
		})
		return err
	}
	return nil
}
