package utils

import (
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"goBastion/internal/models"
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
	n := strings.ToLower(strings.TrimSpace(username))
	n = strings.ReplaceAll(n, "/", "_")
	n = strings.ReplaceAll(n, "..", "_")
	return n
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

// ── Access table rendering ─────────────────────────────────────────────────

// AccessRow is a display-friendly representation of a SelfAccess or GroupAccess.
type AccessRow struct {
	ID             uuid.UUID
	Username       string
	Server         string
	Port           int64
	Protocol       string
	Comment        string
	AllowedFrom    string
	ExpiresAt      *time.Time
	LastConnection time.Time
	CreatedAt      time.Time
}

// SelfAccessToRow converts a models.SelfAccess to an AccessRow.
func SelfAccessToRow(a models.SelfAccess) AccessRow {
	return AccessRow{
		ID:             a.ID,
		Username:       a.Username,
		Server:         a.Server,
		Port:           a.Port,
		Protocol:       a.Protocol,
		Comment:        a.Comment,
		AllowedFrom:    a.AllowedFrom,
		ExpiresAt:      a.ExpiresAt,
		LastConnection: a.LastConnection,
		CreatedAt:      a.CreatedAt,
	}
}

// GroupAccessToRow converts a models.GroupAccess to an AccessRow.
func GroupAccessToRow(a models.GroupAccess) AccessRow {
	return AccessRow{
		ID:             a.ID,
		Username:       a.Username,
		Server:         a.Server,
		Port:           a.Port,
		Protocol:       a.Protocol,
		Comment:        a.Comment,
		AllowedFrom:    a.AllowedFrom,
		ExpiresAt:      a.ExpiresAt,
		LastConnection: a.LastConnection,
		CreatedAt:      a.CreatedAt,
	}
}

// RenderAccessTable renders a formatted table of AccessRow entries and returns body lines.
func RenderAccessTable(rows []AccessRow) []string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tUsername\tServer\tPort\tProtocol\tComment\tFrom\tExpires\tLast Used\tCreated At")
	for _, row := range rows {
		lastUsed := "Never"
		if !row.LastConnection.IsZero() {
			lastUsed = row.LastConnection.Format("2006-01-02 15:04:05")
		}
		expires := "Never"
		if row.ExpiresAt != nil {
			if row.ExpiresAt.Before(time.Now()) {
				expires = "EXPIRED(" + row.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expires = row.ExpiresAt.Format("2006-01-02")
			}
		}
		allowedFrom := row.AllowedFrom
		if allowedFrom == "" {
			allowedFrom = "*"
		}
		proto := row.Protocol
		if proto == "" {
			proto = "ssh"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
			row.ID.String(),
			row.Username,
			row.Server,
			row.Port,
			proto,
			row.Comment,
			allowedFrom,
			expires,
			lastUsed,
			row.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()
	return strings.Split(strings.TrimSpace(buf.String()), "\n")
}

// ── Key rendering ──────────────────────────────────────────────────────────

// KeySection holds a subtitle and body lines for a single key display block.
type KeySection struct {
	SubTitle string
	Body     []string
}

// RenderEgressKeysTable renders egress keys as formatted KeySection entries.
func RenderEgressKeysTable(keys []models.SelfEgressKey) []KeySection {
	sections := make([]KeySection, len(keys))
	for i, key := range keys {
		sections[i] = KeySection{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.PubKey),
			},
		}
	}
	return sections
}

// RenderIngressKeysTable renders ingress keys as formatted KeySection entries.
func RenderIngressKeysTable(keys []models.IngressKey) []KeySection {
	sections := make([]KeySection, len(keys))
	for i, key := range keys {
		expires := "Never"
		if key.ExpiresAt != nil {
			if key.ExpiresAt.Before(time.Now()) {
				expires = "⚠️ EXPIRED (" + key.ExpiresAt.Format("2006-01-02") + ")"
			} else {
				expires = key.ExpiresAt.Format("2006-01-02")
			}
		}
		pivLabel := ""
		if key.PIVAttested {
			pivLabel = " 🔐 PIV-attested"
		}
		sections[i] = KeySection{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s%s", key.Type, pivLabel),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Expires: %s", expires),
				fmt.Sprintf("Last Update: %s", key.UpdatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.Key),
			},
		}
	}
	return sections
}

// ── Role coloring ──────────────────────────────────────────────────────────

// RoleColor returns the colored role string for a UserGroup.
func RoleColor(ug models.UserGroup) string {
	switch {
	case ug.IsOwner():
		return FgRedB(ug.Role)
	case ug.IsGateKeeper():
		return FgYellowB(ug.Role)
	case ug.IsACLKeeper():
		return FgBlueB(ug.Role)
	case ug.IsMember():
		return FgGreenB(ug.Role)
	case ug.IsGuest():
		return FgCyanB(ug.Role)
	default:
		return ug.Role
	}
}
