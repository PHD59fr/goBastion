package utils

import (
	"slices"
	"strings"

	"goBastion/models"
)

func GetGrades(ug models.UserGroup) string {
	var grades []string
	if ug.IsOwner() {
		grades = append(grades, "Owner")
	}
	if ug.IsACLKeeper() {
		grades = append(grades, "ACL Keeper")
	}
	if ug.IsGateKeeper() {
		grades = append(grades, "Gate Keeper")
	}
	if ug.IsMember() {
		grades = append(grades, "Member")
	}
	if ug.IsGuest() {
		grades = append(grades, "Guest")
	}
	if len(grades) == 0 {
		return "None"
	}
	return strings.Join(grades, ", ")
}

func CheckGrade(grade string) bool {
	grade = strings.ToLower(grade)
	return slices.ContainsFunc(models.Grades, func(g string) bool {
		return strings.ToLower(g) == grade
	})
}
