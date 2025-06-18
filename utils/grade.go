package utils

import (
	"strings"

	"goBastion/models"
)

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
