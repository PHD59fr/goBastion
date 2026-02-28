package utils

import (
	"strings"

	"github.com/fatih/color"
	"goBastion/models"
)

// ── Foreground colors ─────────────────────────────────────────────────────────

var FgYellow = color.New(color.FgYellow).SprintFunc()
var FgMagenta = color.New(color.FgMagenta).SprintFunc()
var FgWhite = color.New(color.FgWhite).SprintFunc()
var FgCyan = color.New(color.FgCyan).SprintFunc()
var FgBlue = color.New(color.FgBlue).SprintFunc()
var FgRed = color.New(color.FgRed).SprintFunc()
var FgGreen = color.New(color.FgGreen).SprintFunc()

var FgYellowB = color.New(color.FgYellow, color.Bold).SprintFunc()
var FgMagentaB = color.New(color.FgMagenta, color.Bold).SprintFunc()
var FgWhiteB = color.New(color.FgWhite, color.Bold).SprintFunc()
var FgCyanB = color.New(color.FgCyan, color.Bold).SprintFunc()
var FgBlueB = color.New(color.FgBlue, color.Bold).SprintFunc()
var FgRedB = color.New(color.FgRed, color.Bold).SprintFunc()
var FgGreenB = color.New(color.FgGreen, color.Bold).SprintFunc()

// ── Background colors ─────────────────────────────────────────────────────────

var BgYellow = color.New(color.BgYellow).SprintFunc()
var BgMagenta = color.New(color.BgMagenta).SprintFunc()
var BgWhite = color.New(color.BgWhite).SprintFunc()
var BgCyan = color.New(color.BgCyan).SprintFunc()
var BgBlue = color.New(color.BgBlue).SprintFunc()
var BgRed = color.New(color.BgRed).SprintFunc()
var BgGreen = color.New(color.BgGreen).SprintFunc()

var BgYellowB = color.New(color.BgYellow, color.Bold).SprintFunc()
var BgMagentaB = color.New(color.BgMagenta, color.Bold).SprintFunc()
var BgWhiteB = color.New(color.BgWhite, color.Bold).SprintFunc()
var BgCyanB = color.New(color.BgCyan, color.Bold).SprintFunc()
var BgBlueB = color.New(color.BgBlue, color.Bold).SprintFunc()
var BgRedB = color.New(color.BgRed, color.Bold).SprintFunc()
var BgGreenB = color.New(color.BgGreen, color.Bold).SprintFunc()

// ── String utilities ──────────────────────────────────────────────────────────

// NormalizeUsername lowercases and trims a username.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// ── Role helpers ──────────────────────────────────────────────────────────────

// GetRoles returns a human-readable, comma-separated list of roles for a UserGroup.
func GetRoles(ug models.UserGroup) string {
	var roles []string
	if ug.IsOwner() {
		roles = append(roles, "Owner")
	}
	if ug.IsACLKeeper() {
		roles = append(roles, "ACL Keeper")
	}
	if ug.IsGateKeeper() {
		roles = append(roles, "Gate Keeper")
	}
	if ug.IsMember() {
		roles = append(roles, "Member")
	}
	if ug.IsGuest() {
		roles = append(roles, "Guest")
	}
	if len(roles) == 0 {
		return "None"
	}
	return strings.Join(roles, ", ")
}
