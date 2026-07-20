package models

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// canDoInGroup checks whether any of the user's group memberships satisfies roleCheck.
// If target is non-empty, at least one group with that name must pass roleCheck.
// If target is empty, it returns true when the user has the required role in ANY group
// (used for pre-dispatch availability checks in help/autocomplete).
func (u *User) canDoInGroup(userGroups []UserGroup, target string, roleCheck func(*UserGroup) bool) bool {
	hasRoleInAny := false
	for i := range userGroups {
		ug := &userGroups[i]
		if roleCheck(ug) {
			hasRoleInAny = true
			if target == "" || ug.Group.Name == target {
				return true
			}
		}
	}
	// target == "" and user has the role somewhere → allowed (pre-dispatch check).
	return hasRoleInAny && target == ""
}

// isManagerOrAbove returns true for owner, aclkeeper, gatekeeper roles.
func isManagerOrAbove(ug *UserGroup) bool {
	return ug.IsOwner() || ug.IsACLKeeper() || ug.IsGateKeeper()
}

// isManagerOrMember returns true for owner, aclkeeper, gatekeeper, member roles.
func isManagerOrMember(ug *UserGroup) bool {
	return ug.IsOwner() || ug.IsACLKeeper() || ug.IsGateKeeper() || ug.IsMember()
}

// isOwnerOrACLKeeper returns true for owner and aclkeeper roles.
func isOwnerOrACLKeeper(ug *UserGroup) bool {
	return ug.IsOwner() || ug.IsACLKeeper()
}

// CanDo returns true if the user has permission to perform the given right on the target.
func (u *User) CanDo(db *gorm.DB, right string, target string) bool {
	if u == nil {
		return false
	}

	switch right {
	// Account
	case "accountAddAccess":
		return u.IsAdmin()
	case "accountCreate":
		return u.IsAdmin()
	case "accountDelAccess":
		return u.IsAdmin()
	case "accountDelete":
		return u.IsAdmin()
	case "accountInfo":
		return u.IsAdmin()
	case "accountList":
		return u.IsAdmin()
	case "accountListAccess":
		return u.IsAdmin()
	case "accountListEgressKeys":
		return u.IsAdmin()
	case "accountListIngressKeys":
		return u.IsAdmin()
	case "accountModify":
		return u.IsAdmin()
	case "accountDisableTOTP":
		return u.IsAdmin()
	case "accountUnexpire":
		return u.IsAdmin()
	case "accountExpire":
		return u.IsAdmin()
	case "pivAddTrustAnchor", "pivListTrustAnchors", "pivRemoveTrustAnchor":
		return u.canDoRestricted(db, right)
	case "whoHasAccessTo":
		return u.IsAdmin()

	case "accountSetPassword":
		return u.IsAdmin()

	// Bastion Config
	case "bastionConfig":
		return u.IsAdmin()

	case "realmCreate", "realmDelete", "realmList", "realmInfo":
		return u.canDoRestricted(db, right)

	case "restrictedGrantAdd", "restrictedGrantDel", "restrictedGrantList":
		return u.IsAdmin() || u.IsSuperOwner()

	// Group
	case "groupAddAccess", "groupDelAccess":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrAbove)

	case "groupListAccesses":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrMember)

	case "groupAddAlias", "groupDelAlias":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrAbove)

	case "groupListAliases":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrMember)

	case "groupSetMFA":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, func(ug *UserGroup) bool { return ug.IsOwner() })

	case "groupAddMember", "groupDelMember":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isOwnerOrACLKeeper)

	case "groupAddGuestAccess", "groupDelGuestAccess":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrAbove)

	case "groupListGuestAccesses":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrMember)

	case "groupCreate", "groupDelete":
		return u.IsAdmin()

	case "groupGenerateEgressKey":
		if u.IsAdmin() {
			return true
		}
		if u.IsSuperOwner() {
			return true
		}
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, func(ug *UserGroup) bool { return ug.IsOwner() })

	case "groupInfo", "groupList":
		return true

	case "groupListEgressKeys":
		return true

	// Self
	case "selfAddAccess":
		return true
	case "selfAddAlias":
		return true
	case "selfAddIngressKey":
		return true
	case "selfDelAccess":
		return true
	case "selfDelAlias":
		return true
	case "selfDelIngressKey":
		return true
	case "selfGenerateEgressKey":
		return true
	case "selfListAccesses":
		return true
	case "selfListAliases":
		return true
	case "selfListEgressKeys":
		return true
	case "selfListIngressKeys":
		return true
	case "selfRemoveHostFromKnownHosts":
		return true
	case "selfReplaceKnownHost":
		return true
	case "selfSetupTOTP":
		return true
	case "selfDisableTOTP":
		return true
	case "selfAddIngressKeyPIV":
		return true
	case "selfSetPassword", "selfChangePassword", "selfDisablePassword":
		return true

	// TTY
	case "ttyList", "ttyPlay":
		if u.IsAdmin() {
			return true
		}
		if target == "" {
			return true
		}
		if target == u.Username {
			return true
		}
		return false

	// Misc
	case "help":
		return true
	case "info":
		return true
	case "exit":
		return true

	default:
		return false
	}
}

// restrictedCmdsEnabled is the live state of the restricted-commands master
// kill-switch. config sets it from the DB-backed config on each load/reload.
// It defaults to true (feature on) so behaviour is unchanged before config loads.
var restrictedCmdsEnabled atomic.Bool

func init() {
	restrictedCmdsEnabled.Store(true)
}

// SetRestrictedCmdsEnabled updates the restricted-commands kill-switch.
// Safe for concurrent use.
func SetRestrictedCmdsEnabled(v bool) {
	restrictedCmdsEnabled.Store(v)
}

func (u *User) canDoRestricted(db *gorm.DB, right string) bool {
	// Master kill-switch: when the restricted-command feature is disabled, no
	// restricted right can be exercised (admins included, to fully disable it).
	if !restrictedCmdsEnabled.Load() {
		return false
	}
	if u.IsAdmin() || u.IsSuperOwner() {
		return true
	}
	var count int64
	err := db.Model(&RestrictedCommandGrant{}).
		Where("user_id = ? AND command = ?", u.ID, strings.TrimSpace(right)).
		Count(&count).Error
	if err != nil {
		slog.Warn("canDoRestricted: db query failed", "error", err, "user", u.Username, "right", right)
		return false
	}
	return count > 0
}

// groupsCache is a process-wide cache of group memberships keyed by user ID.
// Entries expire after groupsCacheTTL to avoid stale permission grants.
var (
	groupsCacheMu sync.RWMutex
	groupsCache   = make(map[uuid.UUID]groupsCacheEntry)
)

const groupsCacheTTL = 5 * time.Minute

type groupsCacheEntry struct {
	groups    []UserGroup
	createdAt time.Time
}

// getGroups returns all group memberships for the user.
// Results are cached for a short TTL to avoid repeated DB queries within a
// single session while still picking up membership changes promptly.
func (u *User) getGroups(db *gorm.DB) ([]UserGroup, error) {
	groupsCacheMu.RLock()
	entry, ok := groupsCache[u.ID]
	groupsCacheMu.RUnlock()

	if ok && time.Since(entry.createdAt) < groupsCacheTTL {
		return entry.groups, nil
	}

	var userGroups []UserGroup
	if err := db.Preload("Group").Where("user_id = ?", u.ID).Find(&userGroups).Error; err != nil {
		return nil, fmt.Errorf("error retrieving user groups: %w", err)
	}

	groupsCacheMu.Lock()
	groupsCache[u.ID] = groupsCacheEntry{groups: userGroups, createdAt: time.Now()}
	groupsCacheMu.Unlock()

	return userGroups, nil
}

// InvalidateGroupsCache clears the cached groups so the next CanDo call re-queries the DB.
func InvalidateGroupsCache(userID uuid.UUID) {
	groupsCacheMu.Lock()
	delete(groupsCache, userID)
	groupsCacheMu.Unlock()
}
