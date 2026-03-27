package tty

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// TtyPlay replays a recorded TTY session.
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
		return fmt.Errorf("failed to create pipe: %v", err)
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

// extractDate parses the date from a ttyrec filename.
func extractDate(fileName string) (string, bool) {
	re := regexp.MustCompile(`_(\d{4}-\d{2}-\d{2})_`)
	matches := re.FindStringSubmatch(fileName)
	if len(matches) == 2 {
		return matches[1], true
	}
	return "", false
}
