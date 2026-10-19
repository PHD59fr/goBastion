package self

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/system"

	"gorm.io/gorm"
)

type catalogOptions struct {
	search, group, kind string
	details, all        bool
}

// ListAllAccesses displays the current user's personal, group and guest access
// assignments. The command only reads metadata and never probes target servers.
func ListAllAccesses(db *gorm.DB, user *models.User, args []string) error {
	if user == nil {
		return fmt.Errorf("an authenticated user is required")
	}
	var opts catalogOptions
	fs := flag.NewFlagSet("selfListAllAccesses", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)
	fs.StringVar(&opts.search, "search", "", "Search aliases, hosts, groups, usernames and comments")
	fs.StringVar(&opts.group, "group", "", "Only show accesses from this group")
	fs.StringVar(&opts.kind, "type", "", "Access type: ssh or db")
	fs.BoolVar(&opts.details, "details", false, "Show connection commands, expiry, source CIDRs and MFA")
	fs.BoolVar(&opts.all, "all", false, "Include expired access assignments")
	if err := fs.Parse(args); err != nil {
		return catalogError(err)
	}
	if fs.NArg() != 0 {
		return catalogError(fmt.Errorf("unexpected argument %q; use --search <text>", fs.Arg(0)))
	}
	if opts.kind != "" && opts.kind != "ssh" && opts.kind != "db" {
		return catalogError(fmt.Errorf("invalid type %q: use ssh or db", opts.kind))
	}
	entries, err := loadAccessCatalog(db, user, opts.kind)
	if err != nil {
		return catalogError(fmt.Errorf("retrieve access catalog: %w", err))
	}
	now := time.Now()
	var filtered []catalogAccess
	for _, entry := range entries {
		if !opts.all && entry.expires != nil && !entry.expires.After(now) {
			continue
		}
		if opts.group != "" && !strings.EqualFold(entry.group, opts.group) {
			continue
		}
		text := strings.Join([]string{entry.target(), entry.host, entry.username, entry.database, entry.group,
			entry.source, entry.comment, entry.protocol, strings.Join(entry.aliases, " ")}, " ")
		if opts.search != "" && !strings.Contains(strings.ToLower(text), strings.ToLower(opts.search)) {
			continue
		}
		sort.Strings(entry.aliases)
		filtered = append(filtered, entry)
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		a, b := filtered[i], filtered[j]
		return strings.Join([]string{a.kind, a.host, a.username, a.protocol, a.database, a.source, fmt.Sprint(a.port)}, "\x00") <
			strings.Join([]string{b.kind, b.host, b.username, b.protocol, b.database, b.source, fmt.Sprint(b.port)}, "\x00")
	})
	body := []string{"No matching accesses found."}
	if len(filtered) > 0 {
		body = renderCatalog(filtered, user, now, opts.details)
	}
	console.DisplayBlock(console.ContentBlock{
		Title: "My Access Catalog", BlockType: "info",
		Sections: []console.SectionContent{{SubTitle: fmt.Sprintf("%d access assignment(s)", len(filtered)), Body: body}},
		Footer:   "Use --search <text> to filter, --details for connection hints, --all to include expired accesses.",
	})
	return nil
}

func catalogError(err error) error {
	console.DisplayBlock(console.ContentBlock{Title: "My Access Catalog", BlockType: "error",
		Sections: []console.SectionContent{{SubTitle: "Error", Body: []string{err.Error(),
			"Usage: selfListAllAccesses [--search <text>] [--group <name>] [--type ssh|db] [--details] [--all]"}}}})
	return err
}

func renderCatalog(entries []catalogAccess, user *models.User, now time.Time, details bool) []string {
	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "TYPE\tALIAS\tTARGET\tSOURCE\tSTATUS")
	for _, entry := range entries {
		alias := strings.Join(entry.aliases, ", ")
		if alias == "" {
			alias = "-"
		}
		target := entry.target()
		if entry.database != "" {
			target += "/" + entry.database
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", strings.ToUpper(entry.protocol),
			catalogText(alias), catalogText(target), catalogText(entry.source), catalogStatus(entry, now))
	}
	_ = w.Flush()
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if !details {
		return lines
	}
	for _, entry := range entries {
		expires := "Never"
		if entry.expires != nil {
			expires = entry.expires.Format(time.RFC3339)
		}
		mfa := "Not required"
		if entry.mfa || user.TOTPEnabled || user.PasswordHash != "" || config.Get().RequireMFA.Enabled {
			mfa = "Required"
		}
		lines = append(lines, "", catalogText(entry.target()+" ("+entry.source+")"),
			"  "+catalogConnection(entry), "  Expires: "+expires, "  MFA: "+mfa)
		if entry.kind == "ssh" {
			key := "Missing"
			if entry.hasKey {
				key = "Present"
			}
			lines = append(lines, "  Egress key: "+key)
		}
		var restrictions []string
		for _, cidrs := range entry.cidrs {
			if cidrs != "" {
				restrictions = append(restrictions, catalogText(cidrs))
			}
		}
		if len(restrictions) == 0 {
			restrictions = append(restrictions, "Any")
		}
		lines = append(lines, "  Source CIDRs: "+strings.Join(restrictions, " AND "))
		if entry.comment != "" {
			lines = append(lines, "  Comment: "+catalogText(entry.comment))
		}
	}
	return append(lines, "", "Replace BASTION with your workstation's SSH host alias (configured user and port).",
		"Connection checks still apply. Granted describes an assignment, not network reachability.")
}

func catalogStatus(a catalogAccess, now time.Time) string {
	var reasons []string
	if a.expires != nil && !a.expires.After(now) {
		reasons = append(reasons, "Expired")
	}
	for _, cidrs := range a.cidrs {
		if !catalogSourceAllowed(cidrs) {
			reasons = append(reasons, "Source IP blocked")
			break
		}
	}
	if a.kind == "ssh" && !a.hasKey {
		reasons = append(reasons, "Missing key")
	}
	if a.kind == "ssh" && config.Get().DenyRootTarget.Enabled &&
		(a.username == "root" || a.username == "*" && config.Get().Security.DefaultWildcardUsername == "root") {
		reasons = append(reasons, "Root target blocked")
	}
	switch a.protocol {
	case "ssh":
		if !config.Get().SSH.Enabled {
			reasons = append(reasons, "Interactive SSH disabled")
		}
	case "sftp":
		if !config.Get().SFTP.Enabled {
			reasons = append(reasons, "SFTP disabled")
		}
	case "scpupload", "scpdownload":
		if !config.Get().SCP.Enabled {
			reasons = append(reasons, "SCP disabled")
		}
	case "rsync":
		if !config.Get().RSync.Enabled {
			reasons = append(reasons, "Rsync disabled")
		}
	}
	if len(reasons) == 0 {
		return "Granted"
	}
	return strings.Join(reasons, "; ")
}

func catalogSourceAllowed(cidrs string) bool {
	if cidrs == "" {
		return true
	}
	ip := net.ParseIP(system.ClientIPFromEnv())
	for _, cidr := range strings.Split(cidrs, ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func catalogConnection(a catalogAccess) string {
	if a.kind == "db" {
		command := "ssh -t BASTION -- --db " + catalogQuote(a.target()+":"+a.protocol)
		if a.database != "" {
			command += " --dbname " + catalogQuote(a.database)
		}
		return "Connect: " + command
	}
	if a.protocol != "ssh" {
		return "Transfer target: " + catalogText(a.target()) + " (" + a.protocol + "; use your transfer client through the bastion)"
	}
	if a.username == "*" {
		a.username = config.Get().Security.DefaultWildcardUsername
	}
	return "Connect: ssh -t BASTION -- " + catalogQuote(a.target())
}

// Catalog fields may contain user-entered comments or legacy names. Keep them
// on one terminal line and prevent terminal control sequences in discovery output.
func catalogText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
}

func catalogQuote(value string) string {
	return "'" + strings.ReplaceAll(catalogText(value), "'", "'\"'\"'") + "'"
}
