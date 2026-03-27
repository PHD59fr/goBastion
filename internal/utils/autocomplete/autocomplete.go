package autocomplete

import (
	"sort"
	"strings"

	"goBastion/internal/commands/registry"
	"goBastion/internal/models"

	"github.com/c-bata/go-prompt"
	"gorm.io/gorm"
)

// Completion returns autocomplete suggestions based on the current input and user permissions.
func Completion(d prompt.Document, user *models.User, db *gorm.DB) []prompt.Suggest {
	hasPerm := func(perm string) bool {
		return user.CanDo(db, perm, "")
	}

	text := d.TextBeforeCursor()
	tokens := strings.Fields(text)

	filterAlreadyUsed := func(sugs []prompt.Suggest) []prompt.Suggest {
		var result []prompt.Suggest
		for _, s := range sugs {
			if !contains(tokens, s.Text) {
				result = append(result, s)
			}
		}
		return result
	}

	cmds := registry.BuildRegistry(db, user, nil, nil, nil, nil)

	if len(tokens) > 0 {
		cmd := tokens[0]

		// Check if we should suggest args for this command
		args := registry.PromptArgs(cmds, cmd, hasPerm)
		if args != nil {
			// ttyList/ttyPlay: add --user for admins
			if (cmd == "ttyList" || cmd == "ttyPlay") && user.IsAdmin() {
				args = append(args, prompt.Suggest{Text: "--user", Description: "Username (Admin only)"})
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(args), d.GetWordBeforeCursor(), true)
		}
	}

	// Suggest command names
	suggestions := registry.PromptSuggest(cmds, hasPerm)
	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Text < suggestions[j].Text
	})
	return prompt.FilterHasPrefix(filterAlreadyUsed(suggestions), d.GetWordBeforeCursor(), true)
}

// contains reports whether a string slice contains the given value.
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
