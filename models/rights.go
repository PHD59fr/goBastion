package models

import (
	"fmt"

	"gorm.io/gorm"
)

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
		return true
	case "accountListIngressKeys":
		return u.IsAdmin()
	case "accountModify":
		return u.IsAdmin()
	case "whoHasAccessTo":
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
		isGroupManager := false

		for _, ug := range userGroups {
			if ug.IsOwner() {
				isGroupManager = true
			}
			if ug.GroupID.String() == target && (ug.IsOwner() || ug.IsACLKeeper() || ug.IsGateKeeper()) {
				return true
			}
		}
		return isGroupManager && target == ""

	case "groupListAccesses":
		if u.IsAdmin() {
			return true
		}

		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}

		isGroupManager := false

		for _, ug := range userGroups {
			if ug.IsOwner() {
				isGroupManager = true
			}
			if ug.GroupID.String() == target && (ug.IsOwner() || ug.IsACLKeeper() || ug.IsGateKeeper() || ug.IsMember()) {
				return true
			}
		}
		return isGroupManager && target == ""

	case "groupAddAlias", "groupDelAlias":
		if u.IsAdmin() {
			return true
		}

		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		isGroupManager := false

		for _, ug := range userGroups {
			if ug.IsOwner() {
				isGroupManager = true
			}
			if ug.GroupID.String() == target && (ug.IsOwner() || ug.IsACLKeeper() || ug.IsGateKeeper()) {
				return true
			}
		}
		return isGroupManager && target == ""

	case "groupListAliases":
		if u.IsAdmin() {
			return true
		}

		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}

		isGroupManager := false

		for _, ug := range userGroups {
			if ug.IsOwner() {
				isGroupManager = true
			}
			if ug.GroupID.String() == target && (ug.IsOwner() || ug.IsACLKeeper() || ug.IsGateKeeper() || ug.IsMember()) {
				return true
			}
		}
		return isGroupManager && target == ""

	case "groupAddMember", "groupDelMember":
		if u.IsAdmin() {
			return true
		}

		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		isGroupManager := false

		for _, ug := range userGroups {
			if ug.IsOwner() {
				isGroupManager = true
			}
			if ug.GroupID.String() == target && (ug.IsOwner() || ug.IsACLKeeper()) {
				return true
			}
		}
		return isGroupManager && target == ""

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

		isGroupManager := false

		for _, ug := range userGroups {
			if ug.IsOwner() {
				isGroupManager = true
			}
			if ug.GroupID.String() == target && ug.IsOwner() {
				return true
			}
		}
		return isGroupManager && target == ""

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

func (u *User) getGroups(db *gorm.DB) ([]UserGroup, error) {
	var userGroups []UserGroup
	if err := db.Preload("Group").Where("user_id = ?", u.ID).Find(&userGroups).Error; err != nil {
		return nil, fmt.Errorf("error retrieving user groups: %w", err)
	}
	return userGroups, nil
}
