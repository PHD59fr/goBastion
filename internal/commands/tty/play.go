package tty

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// Play replays a recorded TTY session.
func Play(db *gorm.DB, u *models.User, args []string) error {
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

	if !validation.IsValidUsername(username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Invalid Username", Body: []string{"The specified username is invalid."}},
			},
		})
		return fmt.Errorf("invalid username: %s", username)
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

	if !validRecordingName(file) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Invalid File Format", Body: []string{"The specified file has an invalid format."}},
			},
		})
		return nil
	}

	baseDir := filepath.Join(config.Get().Paths.TtyrecDir, strings.ToLower(strings.TrimSpace(username)))
	ttyFile, err := findRecordingFile(baseDir, file)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "TTY Session Not Found", Body: []string{"Specified TTY Session does not exist"}},
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

	zcatCmd := exec.Command("zcat", ttyFile)
	playCmd := exec.Command("ttyplay")

	pipe, err := zcatCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create pipe: %w", err)
	}
	playCmd.Stdin = pipe
	playCmd.Stdout = os.Stdout
	playCmd.Stderr = os.Stderr

	if err := zcatCmd.Start(); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{
					SubTitle: "Playback Error",
					Body:     []string{fmt.Sprintf("Failed to start zcat: %v", err)},
				},
			},
		})
		return err
	}
	if err := playCmd.Start(); err != nil {
		_ = zcatCmd.Process.Kill()
		console.DisplayBlock(console.ContentBlock{
			Title:     "TTY Session Playback",
			BlockType: "error",
			Sections: []console.SectionContent{
				{
					SubTitle: "Playback Error",
					Body:     []string{fmt.Sprintf("Failed to start ttyplay: %v", err)},
				},
			},
		})
		return err
	}

	// Close the write end of the pipe in this process so ttyplay sees EOF.
	// We need to get the underlying file to close it, but Stdin of zcatCmd
	// is set to os.Stdin, so the pipe's write end is not used by zcatCmd.
	// Just wait for both processes.
	playErr := playCmd.Wait()
	_ = zcatCmd.Wait()

	if playErr != nil && playErr.Error() != "signal: interrupt" && playErr.Error() != "signal: killed" {
		if !errors.Is(playErr, io.EOF) {
			console.DisplayBlock(console.ContentBlock{
				Title:     "TTY Session Playback",
				BlockType: "error",
				Sections: []console.SectionContent{
					{
						SubTitle: "Playback Error",
						Body:     []string{fmt.Sprintf("Failed to play ttyrec file: %v", playErr)},
					},
				},
			})
			return playErr
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

var (
	recordingNameRegexp = regexp.MustCompile(`^(?P<user>[^/]+)\.(?P<server>[^/]+):(?P<port>\d+)_(?P<date>\d{4}-\d{2}-\d{2})_(?P<time>\d{2}-\d{2}-\d{2})(?P<suffix>(?:_[A-Za-z0-9._-]+)*(?:_cmd)?(?:_sid-[a-fA-F0-9-]+)?)\.ttyrec.gz$`)
	dbProtocolRegexp    = regexp.MustCompile(`^(mysql|postgres|redis)$`)
)

func findRecordingFile(baseDir, file string) (string, error) {
	var found string
	errFound := errors.New("recording found")

	err := filepath.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) != file {
			return nil
		}
		found = path
		return errFound
	})
	if err != nil && !errors.Is(err, errFound) {
		return "", err
	}
	if found == "" {
		return "", os.ErrNotExist
	}
	return found, nil
}

// extractDate parses the date from a ttyrec filename.
func extractDate(fileName string) (string, bool) {
	if !validRecordingName(fileName) {
		return "", false
	}
	matches := recordingNameRegexp.FindStringSubmatch(fileName)
	if len(matches) >= 5 {
		return matches[4], true
	}
	return "", false
}

func recordingLabel(file string) string {
	if !validRecordingName(file) {
		return ""
	}
	matches := recordingNameRegexp.FindStringSubmatch(file)
	if len(matches) < 7 {
		return ""
	}
	suffix := strings.TrimPrefix(matches[6], "_")
	if suffix == "" || suffix == "cmd" || strings.HasPrefix(suffix, "sid-") || strings.HasPrefix(suffix, "cmd_sid-") {
		return "SSH"
	}
	first := suffix
	if idx := strings.Index(first, "_"); idx >= 0 {
		first = first[:idx]
	}
	if dbProtocolRegexp.MatchString(first) {
		return "DB/" + first
	}
	return "SSH"
}

func validRecordingName(file string) bool {
	return recordingNameRegexp.MatchString(file) && !strings.Contains(file, "..")
}
