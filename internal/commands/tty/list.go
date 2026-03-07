package tty

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// TtyList lists recorded TTY sessions for a user.
func TtyList(db *gorm.DB, u *models.User, args []string) error {
	fs := flag.NewFlagSet("ttyList", flag.ContinueOnError)
	var startDateStr, endDateStr, hostFilter string
	var username string
	if u.IsAdmin() {
		fs.StringVar(&username, "user", "", "Username (admin only)")
	}
	fs.StringVar(&startDateStr, "startDate", "", "From date (YYYY-MM-DD)")
	fs.StringVar(&endDateStr, "endDate", "", "To date (YYYY-MM-DD)")
	fs.StringVar(&hostFilter, "host", "", "Filter by server hostname")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	bodyUsage := []string{"Usage: ttyList [--host <hostname>] [--startDate <YYYY-MM-DD>] [--endDate <YYYY-MM-DD>]"}
	if u.IsAdmin() {
		bodyUsage = []string{"Usage: ttyList [--user <username>] [--host <hostname>] [--startDate <YYYY-MM-DD>] [--endDate <YYYY-MM-DD>]"}
	}

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: bodyUsage},
			},
		})
		return err
	}

	if username == "" {
		username = u.Username
	}

	if !u.CanDo(db, "ttyList", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to list TTY sessions."}},
			},
		})
		return fmt.Errorf("access denied for user %s to list TTY sessions", u.Username)
	}

	baseDir := fmt.Sprintf("/app/ttyrec/%s/", strings.ToLower(username))
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User %s hasn't recorded any sessions.", username)}},
			},
		})
		return err
	}

	var output []string
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && path != baseDir {
			serverIP := filepath.Base(path)
			if hostFilter != "" && !strings.Contains(serverIP, hostFilter) {
				return filepath.SkipDir
			}
			filesByDate := make(map[string][]string)
			files, err := os.ReadDir(path)
			if err != nil {
				return nil
			}
			// Build a set of gz filenames to deduplicate uncompressed counterparts
			gzSet := make(map[string]bool)
			for _, file := range files {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".ttyrec.gz") {
					gzSet[file.Name()] = true
				}
			}
			for _, file := range files {
				if file.IsDir() {
					continue
				}
				name := file.Name()
				// Skip bare .ttyrec if a .gz version exists
				if strings.HasSuffix(name, ".ttyrec") && !strings.HasSuffix(name, ".ttyrec.gz") {
					if gzSet[name+".gz"] {
						continue
					}
				}
				dateStr, valid := extractDate(name)
				if !valid {
					continue
				}
				if startDateStr != "" {
					start, err := time.Parse("2006-01-02", startDateStr)
					if err == nil {
						d, _ := time.Parse("2006-01-02", dateStr)
						if d.Before(start) {
							continue
						}
					}
				}
				if endDateStr != "" {
					end, err := time.Parse("2006-01-02", endDateStr)
					if err == nil {
						d, _ := time.Parse("2006-01-02", dateStr)
						if d.After(end) {
							continue
						}
					}
				}
				filesByDate[dateStr] = append(filesByDate[dateStr], name)
			}
			if len(filesByDate) == 0 {
				return nil
			}
			output = append(output, utils.FgCyanB("* "+serverIP))
			var sortedDates []string
			for date := range filesByDate {
				sortedDates = append(sortedDates, date)
			}
			sort.Strings(sortedDates)
			for i, date := range sortedDates {
				isLastDate := i == len(sortedDates)-1
				datePrefix := "├── "
				nextPrefix := "│   "
				if isLastDate {
					datePrefix = "└── "
					nextPrefix = "    "
				}
				output = append(output, datePrefix+utils.FgBlue(date))
				sort.Strings(filesByDate[date])
				for j, file := range filesByDate[date] {
					isLastFile := j == len(filesByDate[date])-1
					filePrefix := nextPrefix + "├── "
					if isLastFile {
						filePrefix = nextPrefix + "└── "
					}
					output = append(output, filePrefix+file)
				}
			}
		}
		return nil
	})

	console.DisplayBlock(console.ContentBlock{
		Title:     "TTY Session List",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: fmt.Sprintf("Sessions for %s", username), Body: output},
		},
	})
	return err
}
