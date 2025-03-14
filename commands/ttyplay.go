package commands

import (
	"flag"
	"fmt"
	"goBastion/models"
	"goBastion/utils"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func TtyList(u *models.User, args []string) error {
	fs := flag.NewFlagSet("ttyList", flag.ContinueOnError)
	var startDateStr, endDateStr string
	var username string
	if u.IsAdmin() {
		fs.StringVar(&username, "user", "", "Username (admin only)")
	}
	fs.StringVar(&startDateStr, "startDate", "", "From date (YYYY-MM-DD)")
	fs.StringVar(&endDateStr, "endDate", "", "To date (YYYY-MM-DD)")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		fmt.Println("Usage: ttyList", adminUsage(u))
		return err
	}
	if !u.IsAdmin() {
		username = u.Username
	}
	if username == "" {
		username = u.Username
	}
	baseDir := fmt.Sprintf("/app/ttyrec/%s/", strings.ToLower(username))
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		return fmt.Errorf("user %s hasn't recorded any sessions", username)
	}
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
			fmt.Println(utils.FgBlue("* " + serverIP))
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
				fmt.Println(datePrefix + utils.FgCyan(date))
				sort.Strings(filesByDate[date])
				for j, file := range filesByDate[date] {
					isLastFile := j == len(filesByDate[date])-1
					filePrefix := nextPrefix + "├── "
					if isLastFile {
						filePrefix = nextPrefix + "└── "
					}
					fmt.Println(filePrefix + file)
				}
			}
		}
		return nil
	})
	return err
}

func TtyPlay(u *models.User, args []string) error {
	fs := flag.NewFlagSet("ttyPlay", flag.ContinueOnError)
	var username string
	var file string
	if u.IsAdmin() {
		fs.StringVar(&username, "user", "", "Username (admin only)")
	}
	fs.StringVar(&file, "file", "", "TTY recording file")
	if err := fs.Parse(args); err != nil {
		fmt.Printf("Error parsing flags: %v\n", err)
		fmt.Println("Usage: ttyPlay", adminUsage(u))
		return err
	}
	if !u.IsAdmin() {
		username = u.Username
	}
	if file == "" {
		fmt.Println("Usage: ttyPlay", adminUsage(u))
		return nil
	}
	re := regexp.MustCompile(`^[^.]+\.(?P<server>[^_:]+)(?::\d+)?_\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.ttyrec$`)
	matches := re.FindStringSubmatch(file)
	if len(matches) < 2 {
		fmt.Println("Invalid file format.")
		return nil
	}
	server := matches[1]
	baseDir := fmt.Sprintf("/app/ttyrec/%s/%s/", strings.ToLower(username), server)
	ttyFile := filepath.Join(baseDir, file)
	if _, err := os.Stat(ttyFile); os.IsNotExist(err) {
		fmt.Printf("Specified ttyrec file does not exist: %s\n", ttyFile)
		return nil
	}
	cmd := exec.Command("ttyplay", ttyFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		fmt.Printf("Failed to play ttyrec file: %v\n", err)
		return err
	}
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

func adminUsage(u *models.User) string {
	if u.IsAdmin() {
		return "[--user <username>] --file <ttyrec_file>"
	}
	return "--file <ttyrec_file>"
}
