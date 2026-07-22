package tty

import (
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// List lists recorded TTY sessions for a user.
func List(db *gorm.DB, u *models.User, args []string) error {
	fs := flag.NewFlagSet("ttyList", flag.ContinueOnError)
	var startDate, endDate, hostFilter string
	var username string
	if u.IsAdmin() {
		fs.StringVar(&username, "user", "", "Username (admin only)")
	}
	fs.StringVar(&startDate, "startDate", "", "From date (YYYY-MM-DD)")
	fs.StringVar(&endDate, "endDate", "", "To date (YYYY-MM-DD)")
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

	if !validation.IsValidUsername(username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session List",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Invalid Username", Body: []string{"The specified username is invalid."}},
			},
		})
		return fmt.Errorf("invalid username: %s", username)
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

	baseDir := fmt.Sprintf("%s/%s/", config.Get().Paths.TtyrecDir, strings.ToLower(username))
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
			if err := normalizeLegacyTTYRecs(path, files); err != nil {
				return err
			}
			files, err = os.ReadDir(path)
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
				date, valid := extractDate(name)
				if !valid {
					continue
				}
				if startDate != "" {
					start, err := time.Parse("2006-01-02", startDate)
					if err == nil {
						d, _ := time.Parse("2006-01-02", date)
						if d.Before(start) {
							continue
						}
					}
				}
				if endDate != "" {
					end, err := time.Parse("2006-01-02", endDate)
					if err == nil {
						d, _ := time.Parse("2006-01-02", date)
						if d.After(end) {
							continue
						}
					}
				}
				filesByDate[date] = append(filesByDate[date], name)
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
					label := recordingLabel(file)
					if label != "" {
						output = append(output, filePrefix+fmt.Sprintf("[%s] %s", label, file))
						continue
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

func normalizeLegacyTTYRecs(dir string, files []os.DirEntry) error {
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
		if !strings.HasSuffix(name, ".ttyrec") || strings.HasSuffix(name, ".ttyrec.gz") {
			continue
		}
		gzName := name + ".gz"
		rawPath := filepath.Join(dir, name)
		gzPath := filepath.Join(dir, gzName)
		if gzSet[gzName] {
			if err := os.Remove(rawPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove legacy ttyrec %s: %w", rawPath, err)
			}
			continue
		}
		if err := compressTTYRec(rawPath, gzPath); err != nil {
			return err
		}
		gzSet[gzName] = true
	}
	return nil
}

func compressTTYRec(rawPath, gzPath string) error {
	in, err := os.Open(rawPath)
	if err != nil {
		return fmt.Errorf("open legacy ttyrec %s: %w", rawPath, err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(gzPath)
	if err != nil {
		return fmt.Errorf("create gzip ttyrec %s: %w", gzPath, err)
	}
	gzw := gzip.NewWriter(out)
	if _, err := io.Copy(gzw, in); err != nil {
		_ = gzw.Close()
		_ = out.Close()
		_ = os.Remove(gzPath)
		return fmt.Errorf("compress legacy ttyrec %s: %w", rawPath, err)
	}
	if err := gzw.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(gzPath)
		return fmt.Errorf("finalize gzip ttyrec %s: %w", gzPath, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(gzPath)
		return fmt.Errorf("close gzip ttyrec %s: %w", gzPath, err)
	}
	if err := os.Remove(rawPath); err != nil {
		_ = os.Remove(gzPath)
		return fmt.Errorf("remove legacy ttyrec %s: %w", rawPath, err)
	}
	return nil
}
