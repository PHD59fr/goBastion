package models

import (
	"fmt"

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
	case "pivAddTrustAnchor", "pivListTrustAnchors", "pivRemoveTrustAnchor":
		return u.IsAdmin()
	case "whoHasAccessTo":
		return u.IsAdmin()

	case "accountSetPassword":
		return u.IsAdmin()

	// Group
	case "groupAddAccess", "groupDelAccess":
		if u.IsAdmin() {
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
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrMember)

	case "groupAddAlias", "groupDelAlias":
		if u.IsAdmin() {
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
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrMember)

	case "groupSetMFA":
		if u.IsAdmin() {
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
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isOwnerOrACLKeeper)

	case "groupCreate", "groupDelete":
		return u.IsAdmin()

	case "groupGenerateEgressKey":
		if u.IsAdmin() {
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

// getGroups returns all group memberships for the user.
func (u *User) getGroups(db *gorm.DB) ([]UserGroup, error) {
	var userGroups []UserGroup
	if err := db.Preload("Group").Where("user_id = ?", u.ID).Find(&userGroups).Error; err != nil {
		return nil, fmt.Errorf("error retrieving user groups: %w", err)
	}
	return userGroups, nil
}
