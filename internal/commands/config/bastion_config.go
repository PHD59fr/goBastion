package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"golang.org/x/term"
	"gorm.io/gorm"
)

// ── UI layout constants ──────────────────────────────────────────────────────
// A fixed width (rather than the detected terminal width) is used on purpose:
// in SSH ForceCommand sessions the PTY size is unreliable, and a width larger
// than the real terminal makes the full-width borders wrap and scramble.
const (
	uiWidth  = 62
	contentW = uiWidth - 2     // 60: space inside the left border
	scrollW  = 1               // scrollbar column
	textW    = contentW - scrollW // 59: text area reserved for content
)

// ANSI colors.
const (
	cFrame = "\033[36m"
	cReset = "\033[0m"
	cYellow = "\033[33m"
	cWhite  = "\033[37m"
	cGreen  = "\033[32m"
	cGray   = "\033[90m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cInv    = "\033[47m\033[30m"
)

// ── Categories ───────────────────────────────────────────────────────────────
type category struct {
	name     string
	sections []string
}

var categories = []category{
	{"Core", []string{"ssh", "mfa", "totp", "proxy", "sync", "account", "db_export", "security"}},
	{"Transports", []string{"sftp", "scp", "rsync", "mosh", "realms", "pivs", "guest_access", "interactive"}},
	{"Modes", []string{"readonly", "maintenance", "require_mfa", "force_osh_only"}},
	{"Recording & Sessions", []string{"ttyrec", "session"}},
	{"Features", []string{"self_ingress", "egress_key", "tty_play", "alias_self", "alias_group", "groups", "restricted_grants", "restricted_cmds", "known_hosts", "self_mfa", "self_password", "backup_codes"}},
	{"Connection Policy", []string{"deny_root_target"}},
}

var sectionCategory = map[string]string{}

func init() {
	for _, c := range categories {
		for _, s := range c.sections {
			sectionCategory[s] = c.name
		}
	}
}

// BastionConfig displays the full bastion configuration in an interactive UI.
// Navigation is two-level: a category list, then the entries of the selected
// category. Arrow keys navigate, Enter selects/opens/edits, ← or b goes back,
// r reloads, q quits.
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

	// Enter the alternate screen buffer and hide the cursor so redraws don't
	// flicker or leave the shell prompt visible behind the UI. The table is
	// always redrawn in place (full-width overwrite), so no per-frame clear.
	fmt.Print("\033[?1049h\033[2J\033[?25l")
	defer func() {
		fmt.Print("\033[?25h\033[?1049l")
	}()

	catMode := true
	ccursor, ctop := 0, 0
	activeCat := ""
	ecursor, etop := 0, 0
	var curEntries []displayEntry

	for {
		if catMode {
			ctop = drawCategoryTable(fd, ccursor, ctop)
		} else {
			curEntries = buildDisplayEntries(activeCat)
			etop = drawEntryTable(fd, curEntries, ecursor, etop, activeCat)
		}

		key := readKey(fd)
		config.ResetIdleTimer()
		switch key {
		case "q", "esc", "ctrl+c":
			fmt.Print("\033[?25h\033[?1049l")
			fmt.Printf("\r  Configuration closed.\r\n")
			return nil
		case "left", "b":
			if !catMode {
				catMode = true
			}
		case "enter":
			if catMode {
				if ccursor >= 0 && ccursor < len(categories) {
					activeCat = categories[ccursor].name
					catMode = false
					ecursor, etop = 0, 0
				}
			} else {
				if ecursor < len(curEntries) && !curEntries[ecursor].isSection {
					e := curEntries[ecursor]
					newVal, ok := editLine(fd, e)
					if ok && newVal != e.value {
						if err := applyValue(db, e.key, newVal); err != nil {
							drawStatus(fd, fmt.Sprintf("Error: %v", err), "error")
							readKey(fd)
						}
					}
				}
			}
		case "up":
			if catMode {
				if ccursor > 0 {
					ccursor--
				}
			} else {
				if ecursor > 0 {
					ecursor--
				}
			}
		case "down":
			if catMode {
				if ccursor < len(categories)-1 {
					ccursor++
				}
			} else {
				next := ecursor + 1
				for next < len(curEntries) && curEntries[next].isSection {
					next++
				}
				if next < len(curEntries) {
					ecursor = next
				}
			}
		case "pgup":
			if catMode {
				page := viewportAvail(fd) - 1
				if page < 1 {
					page = 1
				}
				for i := 0; i < page && ccursor > 0; i++ {
					ccursor--
				}
			} else {
				page := viewportAvail(fd) - 1
				if page < 1 {
					page = 1
				}
				for i := 0; i < page && ecursor > 0; i++ {
					ecursor--
					if ecursor < len(curEntries) && curEntries[ecursor].isSection {
						ecursor--
					}
				}
			}
		case "pgdn":
			if catMode {
				page := viewportAvail(fd) - 1
				if page < 1 {
					page = 1
				}
				for i := 0; i < page && ccursor < len(categories)-1; i++ {
					ccursor++
				}
			} else {
				page := viewportAvail(fd) - 1
				if page < 1 {
					page = 1
				}
				for i := 0; i < page; i++ {
					next := ecursor + 1
					for next < len(curEntries) && curEntries[next].isSection {
						next++
					}
					if next < len(curEntries) {
						ecursor = next
					}
				}
			}
		case "r":
			config.Reload(db)
			drawStatus(fd, "Configuration reloaded from database.", "success")
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

// buildDisplayEntries creates the flat list of entries for a category. When
// cat is empty, all entries are returned (used as a fallback).
func buildDisplayEntries(cat string) []displayEntry {
	all := config.ConfigDiff()
	var src []config.ConfigEntry
	if cat == "" {
		src = all
	} else {
		for _, e := range all {
			if sectionCategory[e.Section] == cat {
				src = append(src, e)
			}
		}
	}

	var result []displayEntry
	currentSection := ""
	for _, e := range src {
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

// modifiedInCategory counts entries marked as modified within a category.
func modifiedInCategory(cat string) int {
	n := 0
	for _, e := range config.ConfigDiff() {
		if sectionCategory[e.Section] == cat && e.Modified {
			n++
		}
	}
	return n
}

// drawCategoryTable renders the category list with a viewport + scrollbar.
func drawCategoryTable(fd, cursor, top int) int {
	moveToTop()

	avail := viewportAvail(fd)
	total := len(categories)
	top = clampTop(top, cursor, avail, total)

	drawTopBorder("bastionConfig — Categories")

	for ri := 0; ri < avail; ri++ {
		idx := top + ri
		if idx >= total {
			break
		}
		c := categories[idx]
		label := c.name
		if m := modifiedInCategory(c.name); m > 0 {
			label += fmt.Sprintf("  (%d modified)", m)
		}
		sb := scrollGlyph(ri, avail, top, total)
		line := padVisible(label, textW)
		if idx == cursor {
			fmt.Print(cFrame + "│ " + cReset + invert(line) + sb + "\r\n")
		} else {
			fmt.Print(cFrame + "│ " + cReset + line + sb + "\r\n")
		}
	}

	hint := "↑↓ select  Enter: open  r: reload  q: quit"
	drawFooter(hint, avail, top, total)
	return top
}

// drawEntryTable renders the entries of one category with a viewport + scrollbar.
func drawEntryTable(fd int, entries []displayEntry, cursor, top int, catName string) int {
	moveToTop()

	avail := viewportAvail(fd)
	total := len(entries)
	top = clampTop(top, cursor, avail, total)

	drawTopBorder("bastionConfig — " + catName)

	// max key width (capped).
	maxKey := 0
	for _, e := range entries {
		if !e.isSection && visibleLen(e.label) > maxKey {
			maxKey = visibleLen(e.label)
		}
	}
	if maxKey > 24 {
		maxKey = 24
	}
	if maxKey < 4 {
		maxKey = 4
	}

	for ri := 0; ri < avail; ri++ {
		idx := top + ri
		if idx >= total {
			break
		}
		e := entries[idx]
		sb := scrollGlyph(ri, avail, top, total)

		if e.isSection {
			line := padVisible(cYellow+fit(e.label, textW)+cReset, textW)
			fmt.Print(cFrame + "│ " + cReset + line + sb + "\r\n")
			continue
		}

		markerPlain := " "
		markerStr := " "
		valColor := cWhite
		if e.modified {
			markerPlain = "*"
			markerStr = cYellow + "*" + cReset
			valColor = cGreen
		}

		full := fmt.Sprintf("%s %-*s  %s  (default: %s)", markerPlain, maxKey, e.label, e.value, e.defValue)
		short := fmt.Sprintf("%s %-*s  %s", markerPlain, maxKey, e.label, e.value)
		content := full
		if visibleLen(full) > textW {
			content = short
		}
		if visibleLen(content) > textW {
			content = truncateRunes(content, textW)
		}

		var display string
		switch content {
		case full:
			display = markerStr + fmt.Sprintf(" %-*s  %s%s%s  %s(default: %s)%s",
				maxKey, e.label, valColor, e.value, cReset, cGray, e.defValue, cReset)
		case short:
			display = markerStr + fmt.Sprintf(" %-*s  %s%s%s", maxKey, e.label, valColor, e.value, cReset)
		default:
			display = content
		}
		display = padVisible(display, textW)

		if idx == cursor {
			fmt.Print(cFrame + "│ " + cReset + invert(display) + sb + "\r\n")
		} else {
			fmt.Print(cFrame + "│ " + cReset + display + sb + "\r\n")
		}
	}

	hint := "↑↓ edit  Enter: edit  ←: back  r: reload  q: quit"
	drawFooter(hint, avail, top, total)
	return top
}

// ── Shared drawing helpers ───────────────────────────────────────────────────

// clampTop keeps the cursor visible, returning the adjusted scroll offset.
func clampTop(top, cursor, avail, total int) int {
	if avail < 1 {
		avail = 1
	}
	if top > total-avail {
		top = total - avail
	}
	if top < 0 {
		top = 0
	}
	if cursor < top {
		top = cursor
	}
	if cursor >= top+avail {
		top = cursor - avail + 1
	}
	if top < 0 {
		top = 0
	}
	return top
}

// drawTopBorder prints the title row + mid border.
func drawTopBorder(title string) {
	fmt.Print(cFrame + topBorder(uiWidth) + cReset + "\r\n")
	fmt.Print(cFrame + "│ " + cReset + cBold + padVisible(fit(title, contentW), contentW) + cReset + "\r\n")
	fmt.Print(cFrame + midBorder(uiWidth) + cReset + "\r\n")
}

// drawFooter prints blank filler rows, the hint line(s) and the bottom border.
func drawFooter(hint string, avail, top, total int) {
	visible := total - top
	if visible > avail {
		visible = avail
	}
	if visible < 0 {
		visible = 0
	}
	for i := visible; i < avail; i++ {
		fmt.Print(cFrame + "│ " + cReset + padVisible("", textW) + " \r\n")
	}
	fmt.Print(cFrame + midBorder(uiWidth) + cReset + "\r\n")

	help1 := hint
	help2 := "* = modified from default"
	if total > avail {
		help2 += fmt.Sprintf("   [%d-%d/%d]", top+1, min(top+avail, total), total)
	}
	fmt.Print(cFrame + "│ " + cReset + cGray + padVisible(fit(help1, contentW), contentW) + cReset + "\r\n")
	fmt.Print(cFrame + "│ " + cReset + cGray + padVisible(fit(help2, contentW), contentW) + cReset + "\r\n")
	fmt.Print(cFrame + botBorder(uiWidth) + cReset + "\r\n")
}

// scrollGlyph returns the scrollbar character for a given viewport row.
func scrollGlyph(ri, avail, top, total int) string {
	if total <= avail || avail < 1 {
		return " "
	}
	thumb := (avail * avail) / total
	if thumb < 1 {
		thumb = 1
	}
	ts := (top * avail) / total
	if ts+thumb > avail {
		ts = avail - thumb
	}
	if ri >= ts && ri < ts+thumb {
		return cFrame + "█" + cReset
	}
	return cGray + "│" + cReset
}

// invert wraps s with inverse-video background.
func invert(s string) string {
	return cInv + s + cReset
}

// padVisible pads s (by visible width) with spaces up to n.
func padVisible(s string, n int) string {
	pad := n - visibleLen(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}

// topBorder returns a full-width top frame line, embedding "goBastion".
func topBorder(width int) string {
	const t = "╭───goBastion"
	tc := utf8.RuneCountInString(t)
	if width <= tc {
		return hLine('╭', width)
	}
	return t + strings.Repeat("─", width-tc)
}

// hLine returns a full-width horizontal frame line starting with corner.
func hLine(corner rune, width int) string {
	if width < 2 {
		width = 2
	}
	r := make([]rune, 0, width)
	r = append(r, corner)
	for i := 1; i < width; i++ {
		r = append(r, '─')
	}
	return string(r)
}

func midBorder(width int) string { return hLine('├', width) }
func botBorder(width int) string { return hLine('╰', width) }

// termHeight returns the terminal height, falling back to 40.
func termHeight(fd int) int {
	_, h, err := term.GetSize(fd)
	if err != nil || h < 10 {
		return 40
	}
	return h
}

// viewportAvail returns how many entry rows fit (total height minus the fixed
// header/footer overhead of 6 rows).
func viewportAvail(fd int) int {
	avail := termHeight(fd) - 6
	if avail < 1 {
		avail = 1
	}
	return avail
}

// visibleLen returns the display width of s, ignoring ANSI escape sequences.
func visibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		switch {
		case r == '\033':
			inEsc = true
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		default:
			n++
		}
	}
	return n
}

// truncateRunes truncates s to n runes, appending an ellipsis when cut.
func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:max(1, n)])
	}
	return string(r[:n-1]) + "…"
}

// fit truncates s to n visible runes (with ellipsis) when too long.
func fit(s string, n int) string {
	if visibleLen(s) <= n {
		return s
	}
	return truncateRunes(s, n)
}

// editLine shows an inline edit prompt near the bottom and reads a new value.
// Boolean fields use a selection UI (space / t / f to choose, Enter to
// confirm); other fields are edited as free text.
func editLine(fd int, e displayEntry) (string, bool) {
	h := termHeight(fd)
	row := h - 2
	if row < 3 {
		row = 3
	}

	if e.value == "true" || e.value == "false" {
		cur := e.value == "true"
		redraw := func() {
			fmt.Printf("\033[%d;1H\033[2K", row)
			fmt.Printf(cFrame+"│ "+cReset+cBold+"Edit:"+cReset+" "+cYellow+"%s"+cReset+
				"  "+cGray+"[space/t/f]"+cReset+" → "+cWhite+"%s"+cReset, e.key, boolLabel(cur))
		}
		redraw()
		for {
			b := make([]byte, 1)
			if _, err := os.Stdin.Read(b); err != nil {
				return "", false
			}
			switch b[0] {
			case 13, 10: // Enter
				return strconv.FormatBool(cur), true
			case 27, 3: // Esc / Ctrl+C
				return "", false
			case 32: // space toggles
				cur = !cur
				redraw()
			case 't', 'T':
				cur = true
				redraw()
			case 'f', 'F':
				cur = false
				redraw()
			}
		}
	}

	fmt.Printf("\033[%d;1H\033[2K", row)

	editFmt := cFrame + "│ " + cReset + cBold + "Edit:" + cReset + " " + cYellow + "%s" + cReset + " [" + cWhite + "%s" + cReset + "] → "
	fmt.Printf(editFmt, e.key, e.value)
	fmt.Print(cReset)

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

// boolLabel returns "true"/"false" for a bool.
func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// applyValue updates a config key in the DB.
func applyValue(db *gorm.DB, key, newValue string) error {
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid key format: %s", key)
	}
	section, field := parts[0], parts[1]

	cfg := config.Get()

	// Serialize the full in-memory config (which always contains every section,
	// even ones absent from an older persisted DB row) into a mutable map, then
	// patch the single field. Patching the raw DB JSON directly would fail with
	// "unknown section" for sections that only existed as defaults.
	rawBytes, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(rawBytes, &raw); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	sec, ok := raw[section].(map[string]any)
	if !ok {
		sec = map[string]any{}
		raw[section] = sec
	}

	current := sec[field]
	coerced, err := coerceValue(fmt.Sprintf("%v", current), newValue)
	if err != nil {
		return fmt.Errorf("invalid value: %v", err)
	}

	// Guard: idle_timeout must be at least 30s (0 disables it).
	if key == "session.idle_timeout" {
		if d, perr := parseDurationInput(newValue); perr == nil && d > 0 && d < 30*time.Second {
			return fmt.Errorf("idle_timeout must be at least 30s (use 0 to disable)")
		}
	}

	sec[field] = coerced

	patchedJSON, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}

	// Build a fresh Config from defaults so we don't mutate the shared
	// defaults pointer that GetDefaults() returns.
	patchedCfg := config.DefaultConfig()
	if err := json.Unmarshal(patchedJSON, patchedCfg); err != nil {
		return err
	}
	patchedCfg.Database.Driver = cfg.Database.Driver
	patchedCfg.Database.DSN = cfg.Database.DSN

	return config.SaveConfig(db, patchedCfg)
}

// parseDurationInput parses a duration with the same rules as the config
// Duration type: a bare integer is interpreted as seconds, otherwise it is a
// standard Go duration string (e.g. "30s", "5m").
func parseDurationInput(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(s)
}

// coerceValue converts a string to the correct JSON type based on the current value.
func coerceValue(currentStr, newValue string) (any, error) {
	newValue = strings.TrimSpace(newValue)

	if _, err := strconv.ParseInt(currentStr, 10, 64); err == nil {
		v, err := strconv.ParseInt(newValue, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("expected integer, got %q", newValue)
		}
		return v, nil
	}

	if _, err := strconv.ParseFloat(currentStr, 64); err == nil {
		v, err := strconv.ParseFloat(newValue, 64)
		if err != nil {
			return nil, fmt.Errorf("expected number, got %q", newValue)
		}
		return v, nil
	}

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

	if _, err := strconv.ParseFloat(currentStr, 64); err != nil {
		return newValue, nil
	}

	return newValue, nil
}

// drawStatus shows a temporary status message near the bottom.
func drawStatus(fd int, msg, level string) {
	color := cGreen
	if level == "error" {
		color = cRed
	}
	h := termHeight(fd)
	row := h - 3
	if row < 3 {
		row = 3
	}
	fmt.Printf("\033[%d;1H\033[2K", row)
	fmt.Printf(cFrame+"│ "+cReset+"%s%s"+cReset, color, fit(msg, contentW))
	fmt.Printf("\033[%d;1H\033[2K"+cFrame+"│ "+cReset+cGray+"Press any key..."+cReset, row+1)
	fmt.Printf("\033[%d;1H\033[2K"+cFrame+botBorder(uiWidth)+cReset+"\r\n", row+2)
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
	case 'b':
		return "left"
	}
	return ""
}

// showNonInteractive displays config as a static table (fallback).
func showNonInteractive(db *gorm.DB) error {
	instanceID := config.InstanceID()

	var lines []string
	lines = append(lines, fmt.Sprintf("Instance: %s", instanceID))
	lines = append(lines, "")

	for _, c := range categories {
		lines = append(lines, fmt.Sprintf("== %s ==", c.name))
		entries := buildDisplayEntries(c.name)
		currentSection := ""
		for _, e := range entries {
			if e.isSection {
				if currentSection != "" {
					lines = append(lines, "")
				}
				lines = append(lines, fmt.Sprintf("  [%s]", e.section))
				currentSection = e.section
				continue
			}
			marker := "  "
			if e.modified {
				marker = "* "
			}
			lines = append(lines, fmt.Sprintf("    %s%-24s %-18s (default: %s)", marker, e.label, e.value, e.defValue))
		}
		lines = append(lines, "")
	}
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
