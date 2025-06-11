package commands

import (
	"bytes"
	"flag"
	"fmt"
	"goBastion/models"
	"goBastion/utils"
	"goBastion/utils/console"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gorm.io/gorm"
)

func TtyList(db *gorm.DB, u *models.User, args []string) error {
	fs := flag.NewFlagSet("ttyList", flag.ContinueOnError)
	var startDateStr, endDateStr string
	var username string
	if u.IsAdmin() {
		fs.StringVar(&username, "user", "", "Username (admin only)")
	}
	fs.StringVar(&startDateStr, "startDate", "", "From date (YYYY-MM-DD)")
	fs.StringVar(&endDateStr, "endDate", "", "To date (YYYY-MM-DD)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	bodyUsage := []string{"Usage: ttyList [--startDate <YYYY-MM-DD>] [--endDate <YYYY-MM-DD>]"}
	if u.IsAdmin() {
		bodyUsage = []string{"Usage: ttyList [--user <username>] [--startDate <YYYY-MM-DD>] [--endDate <YYYY-MM-DD>]"}
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
			filesByDate := make(map[string][]string)
			files, err := os.ReadDir(path)
			if err != nil {
				return nil
			}
			for _, file := range files {
				if !file.IsDir() {
					dateStr, valid := extractDate(file.Name())
					if valid {
						filesByDate[dateStr] = append(filesByDate[dateStr], file.Name())
					}
				}
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

func TtyPlay(db *gorm.DB, u *models.User, args []string) error {
	fs := flag.NewFlagSet("ttyPlay", flag.ContinueOnError)
	var username string
	var file string
	if u.IsAdmin() {
		fs.StringVar(&username, "user", "", "Username (admin only)")
	}
	fs.StringVar(&file, "file", "", "TTY recording file")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	bodyUsage := []string{"Usage: ttyPlay --file <file>"}
	if u.IsAdmin() {
		bodyUsage = []string{"Usage: ttyPlay --file <file> [--user <username>]"}
	}

	if err := fs.Parse(args); err != nil || file == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
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

	if !u.CanDo(db, "ttyPlay", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to play TTY sessions."}},
			},
		})
		return fmt.Errorf("access denied for user %s to play TTY sessions", u.Username)
	}

	re := regexp.MustCompile(`^[^.]+\.(?P<server>[^_:]+)(?::\d+)?_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.ttyrec.gz$`)
	matches := re.FindStringSubmatch(file)
	if len(matches) < 2 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Invalid File Format", Body: []string{"The specified file has an invalid format."}},
			},
		})
		return nil
	}

	server := matches[1]
	baseDir := fmt.Sprintf("/app/ttyrec/%s/%s/", strings.ToLower(username), server)
	ttyFile := filepath.Join(baseDir, file)

	if _, err := os.Stat(ttyFile); os.IsNotExist(err) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "TTY Session Not Found", Body: []string{fmt.Sprintf("Specified TTY Session does not exist")}},
			},
		})
		return nil
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "TTY Session Playback",
		BlockType: "info",
		Sections: []console.SectionContent{
			{SubTitle: "Playback Started", Body: []string{fmt.Sprintf("Playing file: %s", file)}},
		},
	})

	cmd := exec.Command("sh", "-c", fmt.Sprintf("zcat %s | ttyplay", ttyFile))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		if err.Error() != "signal: interrupt" {
			console.DisplayBlock(console.ContentBlock{
				Title:     "TTY Session Playback",
				BlockType: "error",
				Sections: []console.SectionContent{
					{
						SubTitle: "Playback Error",
						Body:     []string{fmt.Sprintf("Failed to play ttyrec file: %v", err)},
					},
				},
			})
			return err
		}
	}
	fmt.Printf("\n")
	console.DisplayBlock(console.ContentBlock{
		Title:     "TTY Session Playback",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Playback Completed", Body: []string{fmt.Sprintf("Finished playing file: %s", file)}},
		},
	})

	return nil
}

func extractDate(fileName string) (string, bool) {
	re := regexp.MustCompile(`_(\d{4}-\d{2}-\d{2})_`)
	matches := re.FindStringSubmatch(fileName)
	if len(matches) == 2 {
		return matches[1], true
	}
	return "", false
}
