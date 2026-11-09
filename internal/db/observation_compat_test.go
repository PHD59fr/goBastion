package db

import (
	"bytes"
	"testing"

	"goBastion/internal/models"
)

func TestOfflineSecretBackupSupportsPreObservationSchema(t *testing.T) {
	source := openSecretImportDB(t)
	if err := source.Migrator().DropTable(&models.ObservationCounter{}); err != nil {
		t.Fatal(err)
	}
	user := models.User{Username: "legacy-before-observations", Role: models.RoleUser, Enabled: true}
	if err := source.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	backup := exportSecretImportFixture(t, source)
	target := openSecretImportDB(t)
	if err := Import(target, bytes.NewReader(backup), nil); err != nil {
		t.Fatalf("old schema backup cannot restore: %v", err)
	}
	var count int64
	if err := target.Model(&models.User{}).Count(&count).Error; err != nil || count != 1 {
		t.Fatalf("user lost during old schema backup: %v", err)
	}
}

func TestOnlyObservationTableMayBeMissingInOldLogicalBackup(t *testing.T) {
	database := openSecretImportDB(t)
	var tables []exportTable
	for _, model := range ManagedModelsInDependencyOrder() {
		schema, err := parseModelSchema(database, model)
		if err != nil {
			t.Fatal(err)
		}
		if schema.Table != "observation_counters" {
			tables = append(tables, exportTable{Name: schema.Table})
		}
	}
	if err := validateImportTables(database, tables); err != nil {
		t.Fatalf("pre-observation envelope rejected: %v", err)
	}
	for index, table := range tables {
		if table.Name == "users" {
			tables = append(tables[:index], tables[index+1:]...)
			break
		}
	}
	if err := validateImportTables(database, tables); err == nil {
		t.Fatal("missing identity table was accepted")
	}
}
