package help

import (
	"fmt"
	"regexp"
	"strings"

	"goBastion/internal/commands/registry"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/console"
	"goBastion/version"

	"gorm.io/gorm"
)

var (
	ansiRegex  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	spaceRegex = regexp.MustCompile(`\s{2,}`)
)

// stripANSI removes ANSI escape codes from a string.
func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// splitCommandLine splits a help line into command name and description.
func splitCommandLine(line string) (string, string) {
	parts := spaceRegex.Split(line, 2)
	if len(parts) < 2 {
		return line, ""
	}
	return parts[0], parts[1]
}

// DisplayHelpFromRegistry builds help output from the central command registry.
// This is the single source of truth — no duplicated command definitions.
func DisplayHelpFromRegistry(cmds []registry.CommandSpec, db *gorm.DB, user models.User, hasPerm func(string) bool) {
	type cmdEntry struct {
		subCategory string
		line        string
	}

	// Collect commands per category, grouped by subcategory.
	catIndex := make(map[string]int)
	catCmds := make(map[string][]cmdEntry)
	catOrder := []string{}

	for _, c := range cmds {
		if c.Permission != "" && !hasPerm(c.Permission) {
			continue
		}
		line := " " + utils.FgGreen("-") + " " + c.Name + "  " + c.Description
		if _, exists := catIndex[c.Category]; !exists {
			catIndex[c.Category] = len(catOrder)
			catOrder = append(catOrder, c.Category)
		}
		catCmds[c.Category] = append(catCmds[c.Category], cmdEntry{subCategory: c.SubCategory, line: line})
	}

	// Build SectionContent per (category, subcategory).
	// Category title (> MANAGE GROUPS) only on the first subcategory of each category.
	catColor := map[string]func(a ...interface{}) string{
		"MANAGE YOUR ACCOUNT":   utils.FgYellowB,
		"MANAGE OTHER ACCOUNTS": utils.FgRedB,
		"MANAGE GROUPS":         utils.FgMagentaB,
		"TTY SESSIONS":          utils.FgCyanB,
		"MISC COMMANDS":         utils.FgWhiteB,
	}

	catStarted := make(map[string]bool)
	var consoleSections []console.SectionContent
	for _, cat := range catOrder {
		entries := catCmds[cat]

		// Group entries by subcategory
		type subGroup struct {
			subCat string
			lines  []string
		}
		var groups []subGroup
		lastSub := "\x00"
		for _, e := range entries {
			if e.subCategory != lastSub {
				groups = append(groups, subGroup{subCat: e.subCategory})
				lastSub = e.subCategory
			}
			groups[len(groups)-1].lines = append(groups[len(groups)-1].lines, e.line)
		}

		colorFn := utils.FgWhiteB
		if fn, ok := catColor[cat]; ok {
			colorFn = fn
		}

		for _, g := range groups {
			subTitle := ""
			if !catStarted[cat] {
				subTitle = "> " + cat
				catStarted[cat] = true
			}

			subSub := ""
			if g.subCat != "" {
				subSub = " " + g.subCat
			}

			consoleSections = append(consoleSections, console.SectionContent{
				SubTitle:      subTitle,
				SubTitleColor: colorFn,
				SubSubTitle:   subSub,
				Body:          g.lines,
			})
		}
	}

	// Align command names
	globalMaxCmdLen := 0
	for _, sec := range consoleSections {
		for _, line := range sec.Body {
			cmd, _ := splitCommandLine(line)
			visibleCmd := strings.TrimSpace(stripANSI(cmd))
			if len(visibleCmd) > globalMaxCmdLen {
				globalMaxCmdLen = len(visibleCmd)
			}
		}
	}
	for i, sec := range consoleSections {
		for j, line := range sec.Body {
			cmd, desc := splitCommandLine(line)
			visibleCmd := strings.TrimSpace(stripANSI(cmd))
			pad := globalMaxCmdLen - len(visibleCmd)
			consoleSections[i].Body[j] = cmd + strings.Repeat(" ", pad) + "  " + desc
		}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "▶ help",
		BlockType: "help",
		Sections:  consoleSections,
	})
}

// DisplayInfo prints bastion version and system information.
func DisplayInfo() {
	console.DisplayBlock(console.ContentBlock{
		Title:     "Info",
		BlockType: "info",
		Sections: []console.SectionContent{
			{SubTitle: "goBastion", Body: []string{
				fmt.Sprintf("Version: %s", version.Version),
				"Repository: https://github.com/phd59fr/goBastion",
			}},
		},
	})
}
