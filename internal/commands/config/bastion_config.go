package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"golang.org/x/term"
	"gorm.io/gorm"
)

// BastionConfig displays the full bastion configuration in an interactive
// table. Arrow keys navigate, Enter edits, r reloads, q quits.
func BastionConfig(db *gorm.DB, currentUser *models.User) error {
	if !currentUser.CanDo(db, "bastionConfig", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Bastion Config",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to view or modify the configuration."}},
			},
		})
		return nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return showNonInteractive(db)
	}

	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return showNonInteractive(db)
	}
	defer func() { _ = term.Restore(fd, oldState) }()

	cursor := 0
	for {
		entries := buildDisplayEntries()
		drawTable(entries, cursor)

		key := readKey(fd)
		switch key {
		case "q", "esc", "ctrl+c":
			clearScreen()
			moveToTop()
			fmt.Printf("\r  Configuration closed.\r\n")
			return nil
		case "up":
			if cursor > 0 {
				cursor--
			}
		case "down":
			// Skip section headers when navigating.
			next := cursor + 1
			for next < len(entries) && entries[next].isSection {
				next++
			}
			if next < len(entries) {
				cursor = next
			}
		case "pgup":
			for i := 0; i < 10 && cursor > 0; i++ {
				cursor--
				if entries[cursor].isSection {
					cursor--
				}
			}
		case "pgdn":
			for i := 0; i < 10; i++ {
				next := cursor + 1
				for next < len(entries) && entries[next].isSection {
					next++
				}
				if next < len(entries) {
					cursor = next
				}
			}
		case "enter":
			if cursor >= len(entries) || entries[cursor].isSection {
				continue
			}
			e := entries[cursor]
			newVal, ok := editLine(fd, e)
			if ok && newVal != e.value {
				if err := applyValue(db, e.key, newVal); err != nil {
					drawStatus(fmt.Sprintf("Error: %v", err), "error")
					readKey(fd)
				}
			}
		case "r":
			config.Reload(db)
			drawStatus("Configuration reloaded from database.", "success")
			readKey(fd)
		}
	}
}

// displayEntry represents one row in the config table.
type displayEntry struct {
	section   string
	key       string // "section.field"
	label     string
	value     string
	defValue  string
	modified  bool
	isSection bool
}

// buildDisplayEntries creates the flat list of entries for display.
func buildDisplayEntries() []displayEntry {
	entries := config.ConfigDiff()
	var result []displayEntry

	currentSection := ""
	for _, e := range entries {
		if e.Section != currentSection {
			result = append(result, displayEntry{
				section:   e.Section,
				label:     fmt.Sprintf("[%s]", e.Section),
				isSection: true,
			})
			currentSection = e.Section
		}
		result = append(result, displayEntry{
			section:   e.Section,
			key:       e.Section + "." + e.Key,
			label:     e.Key,
			value:     e.Value,
			defValue:  e.Default,
			modified:  e.Modified,
			isSection: false,
		})
	}
	return result
}

// drawTable renders the full config table with cursor highlight.
// Style matches console/block.go: ╭├╰│ frame, 62-char width, no right border.
func drawTable(entries []displayEntry, cursor int) {
	clearScreen()
	moveToTop()

	const (
		frame  = "\033[36m"
		reset  = "\033[0m"
		yellow = "\033[33m"
		white  = "\033[37m"
		green  = "\033[32m"
		gray   = "\033[90m"
		bold   = "\033[1m"
	)

	instanceID := config.InstanceID()

	fmt.Println(frame + "╭───goBastion──────────────────────────────────────────────" + reset)
	fmt.Printf(frame+"│ "+reset+bold+"bastionConfig"+reset+" — Instance: "+yellow+"%s"+reset+"\r\n", instanceID)
	fmt.Println(frame + "├──────────────────────────────────────────────────────────" + reset)

	// Find max key width.
	maxKey := 0
	for _, e := range entries {
		if !e.isSection && len(e.label) > maxKey {
			maxKey = len(e.label)
		}
	}

	row := 0
	for _, e := range entries {
		if e.isSection {
			fmt.Println(frame + "│ " + reset + yellow + e.label + reset)
			row++
			continue
		}

		marker := " "
		valColor := white
		if e.modified {
			marker = yellow + "*" + reset
			valColor = green
		}

		line := fmt.Sprintf(marker+" %-*s  "+valColor+"%-18s"+reset+"  "+gray+"(default: %s)"+reset,
			maxKey, e.label, e.value, e.defValue)

		if row == cursor {
			fmt.Printf(frame+"│ "+reset+"\033[47m\033[30m ▶%-58s"+reset+"\r\n", line)
		} else {
			fmt.Println(frame + "│ " + reset + line)
		}
		row++
	}

	fmt.Println(frame + "├──────────────────────────────────────────────────────────" + reset)
	fmt.Printf(frame+"│ "+reset+gray+"↑↓ navigate  Enter: edit  r: reload from DB  q: quit"+reset+"\r\n")
	fmt.Printf(frame+"│ "+reset+gray+"* = modified from default"+reset+"\r\n")
	fmt.Println(frame + "╰──────────────────────────────────────────────────────────" + reset)
}

// editLine shows an inline edit prompt at the bottom of the screen and reads
// a new value. Runs entirely in raw mode.
func editLine(fd int, e displayEntry) (string, bool) {
	const (
		frame = "\033[36m"
		reset = "\033[0m"
		yellow = "\033[33m"
		white  = "\033[37m"
		bold   = "\033[1m"
	)

	statusRow := 28
	fmt.Printf("\033[%d;1H\033[2K\r\n", statusRow)
	fmt.Printf("\033[%d;1H\033[2K"+frame+"│ "+reset+bold+"Edit:"+reset+" "+yellow+"%s"+reset+" ["+white+"%s"+reset+"] → ",
		statusRow+1, e.key, e.value)
	fmt.Print(reset)

	// Read input character by character in raw mode.
	var buf []byte
	for {
		b := make([]byte, 1)
		if _, err := os.Stdin.Read(b); err != nil {
			return "", false
		}

		switch b[0] {
		case 13, 10: // Enter
			result := strings.TrimSpace(string(buf))
			if result == "" {
				return e.value, false
			}
			return result, true
		case 27: // Esc
			return "", false
		case 3: // Ctrl+C
			return "", false
		case 127, 8: // Backspace
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				fmt.Print("\b \b")
			}
		default:
			if b[0] >= 32 && b[0] < 127 {
				buf = append(buf, b[0])
				fmt.Printf("%c", b[0])
			}
		}
	}
}

// applyValue updates a config key in the DB.
func applyValue(db *gorm.DB, key, newValue string) error {
	cfg := config.Get()

	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid key format: %s", key)
	}

	// Read current raw JSON from DB.
	type row struct {
		Config string
	}
	var r row
	boot := config.GetBootstrap()
	if err := db.Table("bastion_instances").Where("instance_id = ?", boot.InstanceID).Select("config").First(&r).Error; err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var raw map[string]any
	if err := json.Unmarshal([]byte(r.Config), &raw); err != nil {
		return fmt.Errorf("parse config JSON: %w", err)
	}

	section, ok := raw[parts[0]].(map[string]any)
	if !ok {
		return fmt.Errorf("unknown section: %s", parts[0])
	}

	coerced, err := coerceValue(fmt.Sprintf("%v", section[parts[1]]), newValue)
	if err != nil {
		return fmt.Errorf("invalid value: %v", err)
	}
	section[parts[1]] = coerced

	patchedJSON, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}

	patchedCfg := config.GetDefaults()
	if err := json.Unmarshal(patchedJSON, patchedCfg); err != nil {
		return err
	}
	patchedCfg.Database.Driver = cfg.Database.Driver
	patchedCfg.Database.DSN = cfg.Database.DSN

	return config.SaveConfig(db, patchedCfg)
}

// coerceValue converts a string to the correct JSON type based on the current value.
func coerceValue(currentStr, newValue string) (any, error) {
	newValue = strings.TrimSpace(newValue)

	// Integer?
	if _, err := strconv.ParseInt(currentStr, 10, 64); err == nil {
		v, err := strconv.ParseInt(newValue, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("expected integer, got %q", newValue)
		}
		return v, nil
	}

	// Float?
	if _, err := strconv.ParseFloat(currentStr, 64); err == nil {
		v, err := strconv.ParseFloat(newValue, 64)
		if err != nil {
			return nil, fmt.Errorf("expected number, got %q", newValue)
		}
		return v, nil
	}

	// Boolean?
	switch strings.ToLower(currentStr) {
	case "true", "false":
		switch strings.ToLower(newValue) {
		case "true", "1", "yes", "on":
			return true, nil
		case "false", "0", "no", "off":
			return false, nil
		default:
			return nil, fmt.Errorf("expected boolean, got %q", newValue)
		}
	}

	// Duration string? (e.g. "5s", "1h0m0s")
	if _, err := strconv.ParseFloat(currentStr, 64); err != nil {
		// Looks like a duration or string. If current is a duration-like
		// and new value contains time units, accept it.
		return newValue, nil
	}

	return newValue, nil
}

// drawStatus shows a temporary status message at the bottom.
func drawStatus(msg, level string) {
	const (
		frame = "\033[36m"
		reset = "\033[0m"
		gray  = "\033[90m"
	)
	color := "\033[32m"
	if level == "error" {
		color = "\033[31m"
	}
	fmt.Printf("\033[%d;1H\033[2K", 28)
	fmt.Printf("\033[29;1H\033[2K"+frame+"│ "+reset+"%s%s"+reset+"\r\n", color, msg)
	fmt.Printf("\033[30;1H\033[2K"+frame+"│ "+reset+gray+"Press any key..."+reset+"\r\n")
	fmt.Println(frame + "╰──────────────────────────────────────────────────────────" + reset)
}

func clearScreen() {
	fmt.Print("\033[2J")
}

func moveToTop() {
	fmt.Print("\033[1;1H")
}

// readKey reads a single keypress and returns its name.
func readKey(fd int) string {
	buf := make([]byte, 3)
	n, err := os.Stdin.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	if buf[0] == 27 && n >= 3 && buf[1] == 91 {
		switch buf[2] {
		case 65:
			return "up"
		case 66:
			return "down"
		case 67:
			return "right"
		case 68:
			return "left"
		case 53: // PgUp (ESC [ 5 ~)
			_, _ = os.Stdin.Read(make([]byte, 1)) // consume '~'
			return "pgup"
		case 54: // PgDn (ESC [ 6 ~)
			_, _ = os.Stdin.Read(make([]byte, 1)) // consume '~'
			return "pgdn"
		}
	}

	switch buf[0] {
	case 27:
		return "esc"
	case 13, 10:
		return "enter"
	case 3:
		return "ctrl+c"
	case 'q':
		return "q"
	case 'r':
		return "r"
	}
	return ""
}

// showNonInteractive displays config as a static table (fallback).
func showNonInteractive(db *gorm.DB) error {
	entries := config.ConfigDiff()
	instanceID := config.InstanceID()

	var lines []string
	lines = append(lines, fmt.Sprintf("Instance: %s", instanceID))
	lines = append(lines, "")

	currentSection := ""
	for _, e := range entries {
		if e.Section != currentSection {
			if currentSection != "" {
				lines = append(lines, "")
			}
			lines = append(lines, fmt.Sprintf("[%s]", e.Section))
			currentSection = e.Section
		}
		marker := "  "
		if e.Modified {
			marker = "* "
		}
		lines = append(lines, fmt.Sprintf("  %s%-24s %-18s (default: %s)", marker, e.Key, e.Value, e.Default))
	}
	lines = append(lines, "")
	lines = append(lines, "* = modified from default")

	console.DisplayBlock(console.ContentBlock{
		Title:     "Bastion Configuration",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: fmt.Sprintf("Instance: %s", instanceID), Body: lines},
		},
	})
	return nil
}
