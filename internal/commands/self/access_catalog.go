package self

import (
	"net"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/validation"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// catalogAccess contains discovery metadata only, never credentials.
type catalogAccess struct {
	kind, protocol, host, username, database string
	port                                     int64
	source, group, comment                   string
	aliases                                  []string
	expires                                  *time.Time
	cidrs                                    []string // Each list is an additional restriction (AND).
	mfa, hasKey                              bool
}

type catalogAlias struct {
	kind, name, host, protocol string
	port                       int64
}

// loadAccessCatalog lists explicit personal and membership-based assignments.
// Admin and superowner privileges do not turn this into a global inventory.
func loadAccessCatalog(db *gorm.DB, user *models.User, kind string) ([]catalogAccess, error) {
	var memberships []models.UserGroup
	if err := db.Preload("Group").Where("user_id = ?", user.ID).Find(&memberships).Error; err != nil {
		return nil, err
	}
	groups := make(map[uuid.UUID]models.UserGroup)
	var groupIDs, memberIDs, guestIDs []uuid.UUID
	for _, membership := range memberships {
		if membership.Group.ID == uuid.Nil {
			continue // Soft-deleted groups confer no catalog entries.
		}
		if !user.CanViewGroupInfo(db, membership.Group.Name) {
			continue
		}
		groups[membership.GroupID] = membership
		groupIDs = append(groupIDs, membership.GroupID)
		if membership.Role == models.GroupRoleGuest {
			guestIDs = append(guestIDs, membership.GroupID)
		} else {
			memberIDs = append(memberIDs, membership.GroupID)
		}
	}
	var entries []catalogAccess
	if kind != "db" {
		sshEntries, err := loadCatalogSSH(db, user, groups, groupIDs)
		if err != nil {
			return nil, err
		}
		entries = append(entries, sshEntries...)
	}
	if kind != "ssh" && config.Get().Database.Enabled {
		dbEntries, err := loadCatalogDB(db, user, groups, memberIDs, guestIDs)
		if err != nil {
			return nil, err
		}
		entries = append(entries, dbEntries...)
	}
	aliases, err := loadCatalogAliases(db, user.ID, groupIDs, groups, kind)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		entry := &entries[i]
		entry.host = validation.UnbracketHost(entry.host)
		for _, alias := range aliases {
			if alias.kind == entry.kind && validation.UnbracketHost(alias.host) == entry.host &&
				(entry.kind == "ssh" || alias.port == entry.port && alias.protocol == entry.protocol) {
				entry.aliases = append(entry.aliases, alias.name)
			}
		}
	}
	return entries, nil
}

func loadCatalogSSH(db *gorm.DB, user *models.User, groups map[uuid.UUID]models.UserGroup, groupIDs []uuid.UUID) ([]catalogAccess, error) {
	var selfAccesses []models.SelfAccess
	if err := db.Where("user_id = ?", user.ID).Find(&selfAccesses).Error; err != nil {
		return nil, err
	}
	var keyCount int64
	if err := db.Model(&models.SelfEgressKey{}).Where("user_id = ? AND priv_key <> ''", user.ID).Count(&keyCount).Error; err != nil {
		return nil, err
	}
	var entries []catalogAccess
	for _, a := range selfAccesses {
		entries = append(entries, catalogAccess{kind: "ssh", protocol: catalogSSHProtocol(a.Protocol), host: a.Server,
			username: a.Username, port: a.Port, source: "personal", comment: a.Comment,
			expires: a.ExpiresAt, cidrs: []string{a.AllowedFrom}, hasKey: keyCount > 0})
	}
	if len(groupIDs) == 0 {
		return entries, nil
	}
	var groupAccesses []models.GroupAccess
	if err := db.Where("group_id IN ?", groupIDs).Find(&groupAccesses).Error; err != nil {
		return nil, err
	}
	var keyGroups []uuid.UUID
	if err := db.Model(&models.GroupEgressKey{}).Where("group_id IN ? AND priv_key <> ''", groupIDs).
		Distinct().Pluck("group_id", &keyGroups).Error; err != nil {
		return nil, err
	}
	keys := make(map[uuid.UUID]bool)
	for _, id := range keyGroups {
		keys[id] = true
	}
	var grants []models.GroupGuestAccess
	if err := db.Where("user_id = ? AND group_id IN ?", user.ID, groupIDs).Find(&grants).Error; err != nil {
		return nil, err
	}
	for _, a := range groupAccesses {
		membership := groups[a.GroupID]
		entry := catalogAccess{kind: "ssh", protocol: catalogSSHProtocol(a.Protocol), host: a.Server,
			username: a.Username, port: a.Port, source: "group:" + membership.Group.Name, group: membership.Group.Name,
			comment: a.Comment, expires: a.ExpiresAt, cidrs: []string{a.AllowedFrom},
			mfa: membership.Group.MFARequired, hasKey: keys[a.GroupID]}
		if membership.Role != models.GroupRoleGuest {
			entries = append(entries, entry)
			continue
		}
		// SSH guest grants restrict an existing group access; a grant alone is
		// insufficient. Both expiry and source-IP restrictions still apply.
		for _, grant := range grants {
			if grant.GroupID != a.GroupID || grant.Port != a.Port ||
				validation.UnbracketHost(grant.Server) != validation.UnbracketHost(a.Server) ||
				(a.Username != "*" && a.Username != grant.Username) {
				continue
			}
			protocol := catalogSSHProtocol(grant.Protocol)
			if entry.protocol != "ssh" {
				if protocol != "ssh" && protocol != entry.protocol {
					continue
				}
				protocol = entry.protocol
			}
			guestEntry := entry
			guestEntry.source = "guest:" + membership.Group.Name
			guestEntry.username, guestEntry.protocol = grant.Username, protocol
			guestEntry.expires = catalogEarlierExpiry(entry.expires, grant.ExpiresAt)
			guestEntry.cidrs = []string{a.AllowedFrom, grant.AllowedFrom}
			guestEntry.comment = strings.TrimSpace(a.Comment + " " + grant.Comment)
			entries = append(entries, guestEntry)
		}
	}
	return entries, nil
}

func loadCatalogDB(db *gorm.DB, user *models.User, groups map[uuid.UUID]models.UserGroup, memberIDs, guestIDs []uuid.UUID) ([]catalogAccess, error) {
	var personal []models.SelfDBAccess
	if err := db.Omit("Password").Where("user_id = ?", user.ID).Find(&personal).Error; err != nil {
		return nil, err
	}
	var entries []catalogAccess
	for _, a := range personal {
		entries = append(entries, catalogAccess{kind: "db", protocol: a.Protocol, host: a.Host, username: a.Username,
			port: a.Port, database: a.Database, source: "personal", comment: a.Comment, expires: a.ExpiresAt, cidrs: []string{a.AllowedFrom}})
	}
	if len(memberIDs) > 0 {
		var shared []models.GroupDBAccess
		if err := db.Omit("Password").Where("group_id IN ?", memberIDs).Find(&shared).Error; err != nil {
			return nil, err
		}
		for _, a := range shared {
			group := groups[a.GroupID].Group
			entries = append(entries, catalogAccess{kind: "db", protocol: a.Protocol, host: a.Host, username: a.Username,
				port: a.Port, database: a.Database, source: "group:" + group.Name, group: group.Name,
				comment: a.Comment, expires: a.ExpiresAt, cidrs: []string{a.AllowedFrom}, mfa: group.MFARequired})
		}
	}
	if len(guestIDs) > 0 {
		var grants []models.GroupGuestDBAccess
		if err := db.Omit("Password").Where("user_id = ? AND group_id IN ?", user.ID, guestIDs).Find(&grants).Error; err != nil {
			return nil, err
		}
		for _, a := range grants {
			group := groups[a.GroupID].Group
			entries = append(entries, catalogAccess{kind: "db", protocol: a.Protocol, host: a.Host, username: a.Username,
				port: a.Port, database: a.Database, source: "guest:" + group.Name, group: group.Name,
				comment: a.Comment, expires: a.ExpiresAt, cidrs: []string{a.AllowedFrom}, mfa: group.MFARequired})
		}
	}
	return entries, nil
}

func loadCatalogAliases(db *gorm.DB, userID uuid.UUID, groupIDs []uuid.UUID, groups map[uuid.UUID]models.UserGroup, kind string) ([]catalogAlias, error) {
	var out []catalogAlias
	query := func() *gorm.DB {
		if len(groupIDs) > 0 {
			return db.Where("user_id = ? OR group_id IN ?", userID, groupIDs)
		}
		return db.Where("user_id = ?", userID)
	}
	name := func(alias string, groupID *uuid.UUID) string {
		if groupID != nil {
			return groups[*groupID].Group.Name + "-" + alias
		}
		return alias
	}
	if kind != "db" {
		var aliases []models.Aliases
		if err := query().Find(&aliases).Error; err != nil {
			return nil, err
		}
		for _, a := range aliases {
			out = append(out, catalogAlias{kind: "ssh", name: name(a.ResolveFrom, a.GroupID), host: a.Host})
		}
	}
	if kind != "ssh" && config.Get().Database.Enabled {
		var aliases []models.DatabaseAlias
		if err := query().Find(&aliases).Error; err != nil {
			return nil, err
		}
		for _, a := range aliases {
			out = append(out, catalogAlias{kind: "db", name: name(a.ResolveFrom, a.GroupID), host: a.Host, port: a.Port, protocol: a.Protocol})
		}
	}
	return out, nil
}

func catalogEarlierExpiry(a, b *time.Time) *time.Time {
	if a == nil || b != nil && b.Before(*a) {
		return b
	}
	return a
}

func catalogSSHProtocol(protocol string) string {
	if protocol == "" {
		return "ssh"
	}
	return protocol
}

func (a catalogAccess) target() string {
	// Formatting is shared by the compact table and the detailed commands.
	return a.username + "@" + net.JoinHostPort(validation.UnbracketHost(a.host), strconv.FormatInt(a.port, 10))
}
