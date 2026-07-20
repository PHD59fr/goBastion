// Package registry provides the single source of truth for all bastion commands.
// Help, autocomplete, and executeCommand all read from this registry.
package registry

import (
	"log/slog"

	"github.com/c-bata/go-prompt"
	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

// ArgSpec describes a command-line flag for autocomplete.
type ArgSpec struct {
	Name        string
	Description string
}

// CommandSpec is the canonical definition of a single bastion command.
type CommandSpec struct {
	Name        string
	Description string
	Permission  string
	Category    string
	SubCategory string
	Args        []ArgSpec
	Features    []string
	Mutating    bool
	Handler     func() error
}

// BuildRegistry constructs the command registry for a given session context.
// It merges the static command metadata (name, description, args, etc.) from
// commandRegistry with session-specific handler closures built by buildHandlers.
func BuildRegistry(db *gorm.DB, user *models.User, log *slog.Logger, adapter osadapter.SystemAdapter, args []string, exitFunc func()) []CommandSpec {
	handlers := buildHandlers(db, user, log, adapter, args, exitFunc)
	specs := make([]CommandSpec, len(commandRegistry))
	for i, meta := range commandRegistry {
		specs[i] = CommandSpec{
			Name:        meta.Name,
			Description: meta.Description,
			Permission:  meta.Permission,
			Category:    meta.Category,
			SubCategory: meta.SubCategory,
			Args:        meta.Args,
			Features:    meta.Features,
			Mutating:    meta.Mutating,
			Handler:     handlers[meta.Name],
		}
	}
	return specs
}

// PromptSuggest converts the registry to go-prompt suggestions, filtered by permission.
func PromptSuggest(cmds []CommandSpec, hasPerm func(string) bool) []prompt.Suggest {
	var out []prompt.Suggest
	for _, c := range cmds {
		if c.Permission == "" || hasPerm(c.Permission) {
			out = append(out, prompt.Suggest{Text: c.Name, Description: c.Description})
		}
	}
	return out
}

// PromptArgs returns autocomplete suggestions for the given command's flags.
func PromptArgs(cmds []CommandSpec, cmdName string, hasPerm func(string) bool) []prompt.Suggest {
	for _, c := range cmds {
		if c.Name == cmdName {
			if c.Permission != "" && !hasPerm(c.Permission) {
				return nil
			}
			var out []prompt.Suggest
			for _, a := range c.Args {
				out = append(out, prompt.Suggest{Text: a.Name, Description: a.Description})
			}
			return out
		}
	}
	return nil
}
