package models

import (
	"fmt"
	"strings"
	"sync/atomic"

	"gorm.io/gorm"
)

const (
	GroupVisibilityOpen     = "open"
	GroupVisibilityMembers  = "members"
	GroupVisibilityManagers = "managers"
	GroupVisibilityPrivate  = "private"

	EgressKeyVisibilityDiscoverable = "discoverable"
	EgressKeyVisibilityMembers      = "members"
	EgressKeyVisibilityManagers     = "managers"
	EgressKeyVisibilityPrivate      = "private"
)

type VisibilityPolicy struct {
	GroupVisibilityMode     string
	EgressKeyVisibilityMode string
}

type VisibilityDeniedKind string

const (
	VisibilityDeniedGroupPolicy     VisibilityDeniedKind = "group_policy"
	VisibilityDeniedEgressPolicy    VisibilityDeniedKind = "egress_policy"
	VisibilityDeniedGuestOwnOnly    VisibilityDeniedKind = "guest_own_only"
	VisibilityDeniedGlobalGroupList VisibilityDeniedKind = "group_list_all_policy"
)

var groupVisibilityMode atomic.Value
var egressKeyVisibilityMode atomic.Value

func init() {
	groupVisibilityMode.Store(GroupVisibilityOpen)
	egressKeyVisibilityMode.Store(EgressKeyVisibilityDiscoverable)
}

func normalizeGroupVisibilityMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case GroupVisibilityMembers, GroupVisibilityManagers, GroupVisibilityPrivate:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return GroupVisibilityOpen
	}
}

func normalizeEgressKeyVisibilityMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case EgressKeyVisibilityMembers, EgressKeyVisibilityManagers, EgressKeyVisibilityPrivate:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return EgressKeyVisibilityDiscoverable
	}
}

func CurrentVisibilityPolicy() VisibilityPolicy {
	return VisibilityPolicy{
		GroupVisibilityMode:     normalizeGroupVisibilityMode(groupVisibilityMode.Load().(string)),
		EgressKeyVisibilityMode: normalizeEgressKeyVisibilityMode(egressKeyVisibilityMode.Load().(string)),
	}
}

// SetGroupVisibilityMode updates the live group visibility policy.
func SetGroupVisibilityMode(mode string) {
	groupVisibilityMode.Store(normalizeGroupVisibilityMode(mode))
}

// SetEgressKeyVisibilityMode updates the live group egress-key visibility policy.
func SetEgressKeyVisibilityMode(mode string) {
	egressKeyVisibilityMode.Store(normalizeEgressKeyVisibilityMode(mode))
}

func (u *User) CanViewGroupInfo(db *gorm.DB, target string) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin() || u.IsSuperOwner() {
		return true
	}

	switch CurrentVisibilityPolicy().GroupVisibilityMode {
	case GroupVisibilityOpen:
		return true
	case GroupVisibilityMembers, GroupVisibilityPrivate:
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrMemberOrGuest)
	case GroupVisibilityManagers:
		userGroups, err := u.getGroups(db)
		if err != nil {
			return false
		}
		return u.canDoInGroup(userGroups, target, isManagerOrAbove)
	default:
		return true
	}
}

func (u *User) CanViewGroupEgressKeys(db *gorm.DB, target string) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin() || u.IsSuperOwner() {
		return true
	}

	userGroups, err := u.getGroups(db)
	if err != nil {
		return false
	}

	switch CurrentVisibilityPolicy().EgressKeyVisibilityMode {
	case EgressKeyVisibilityDiscoverable:
		return true
	case EgressKeyVisibilityMembers:
		return u.canDoInGroup(userGroups, target, isManagerOrMemberOrGuest)
	case EgressKeyVisibilityManagers:
		return u.canDoInGroup(userGroups, target, isManagerOrAbove)
	case EgressKeyVisibilityPrivate:
		return u.canDoInGroup(userGroups, target, func(ug *UserGroup) bool { return ug.IsOwner() })
	default:
		return true
	}
}

func (u *User) CanListAllGroups(db *gorm.DB) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin() || u.IsSuperOwner() {
		return true
	}
	return CurrentVisibilityPolicy().GroupVisibilityMode == GroupVisibilityOpen
}

func (u *User) CanViewGuestGrantList(db *gorm.DB, target string) bool {
	return u.CanViewGroupInfo(db, target)
}

func (u *User) CanInspectGuestGrantTarget(db *gorm.DB, groupName, account string) bool {
	if !u.CanViewGuestGrantList(db, groupName) {
		return false
	}
	if u.IsAdmin() || u.IsSuperOwner() {
		return true
	}
	userGroups, err := u.getGroups(db)
	if err != nil {
		return false
	}
	for i := range userGroups {
		ug := &userGroups[i]
		if ug.Group.Name != groupName {
			continue
		}
		if ug.IsGuest() {
			return strings.EqualFold(account, u.Username)
		}
		return true
	}
	return false
}

func DescribeVisibilityDenial(kind VisibilityDeniedKind, groupName, account string) []string {
	policy := CurrentVisibilityPolicy()

	switch kind {
	case VisibilityDeniedGroupPolicy:
		lines := []string{
			fmt.Sprintf("You do not have permission to view group '%s' under the current visibility policy.", groupName),
			fmt.Sprintf("Current policy: security.group_visibility.mode=%s", policy.GroupVisibilityMode),
		}
		switch policy.GroupVisibilityMode {
		case GroupVisibilityMembers:
			lines = append(lines, "Required: member, guest, manager, admin, or superowner in the target group.")
		case GroupVisibilityManagers:
			lines = append(lines, "Required: owner, aclkeeper, gatekeeper, admin, or superowner in the target group.")
		case GroupVisibilityPrivate:
			lines = append(lines, "Required: direct group membership, admin, or superowner in the target group.")
		}
		return lines

	case VisibilityDeniedEgressPolicy:
		lines := []string{
			fmt.Sprintf("You do not have permission to list egress keys for group '%s'.", groupName),
			fmt.Sprintf("Current policy: security.egress_key_visibility.mode=%s", policy.EgressKeyVisibilityMode),
		}
		switch policy.EgressKeyVisibilityMode {
		case EgressKeyVisibilityMembers:
			lines = append(lines, "Required: member, guest, manager, admin, or superowner in the target group.")
		case EgressKeyVisibilityManagers:
			lines = append(lines, "Required: owner, aclkeeper, gatekeeper, admin, or superowner in the target group.")
		case EgressKeyVisibilityPrivate:
			lines = append(lines, "Required: group owner, admin, or superowner.")
		}
		return lines

	case VisibilityDeniedGuestOwnOnly:
		return []string{
			"Guest users can only view their own grants in this group.",
			fmt.Sprintf("Requested account: %s", account),
		}

	case VisibilityDeniedGlobalGroupList:
		return []string{
			"You do not have permission to list all groups under the current visibility policy.",
			fmt.Sprintf("Current policy: security.group_visibility.mode=%s", policy.GroupVisibilityMode),
		}
	default:
		return []string{"Access denied under the current visibility policy."}
	}
}
