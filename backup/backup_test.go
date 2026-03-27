package backup

import (
	"encoding/json"
	"testing"
)

type testSecret struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type testSecretV2 struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	HasTotp  bool   `json:"has_totp"`
}

func TestRoundTrip(t *testing.T) {
	// Create archive
	a := NewArchive("warden", 1, 42, false)

	secrets := []testSecret{
		{ID: "s1", Name: "GitHub", Username: "admin"},
		{ID: "s2", Name: "AWS", Username: "root"},
	}
	if err := SetEntities(a, "secrets", secrets); err != nil {
		t.Fatalf("SetEntities: %v", err)
	}

	passwords := map[string]string{"s1": "pass1", "s2": "pass2"}
	if err := SetExtra(a, "secretPasswords", passwords); err != nil {
		t.Fatalf("SetExtra: %v", err)
	}

	// Pack
	data, err := Pack(a)
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	t.Logf("Packed size: %d bytes", len(data))

	// Unpack
	restored, err := Unpack(data)
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}

	// Verify manifest
	if restored.Manifest.Module != "warden" {
		t.Errorf("module = %q, want warden", restored.Manifest.Module)
	}
	if restored.Manifest.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", restored.Manifest.SchemaVersion)
	}
	if restored.Manifest.EntityCounts["secrets"] != 2 {
		t.Errorf("entityCounts[secrets] = %d, want 2", restored.Manifest.EntityCounts["secrets"])
	}

	// Read entities
	got, err := GetEntities[testSecret](restored, "secrets")
	if err != nil {
		t.Fatalf("GetEntities: %v", err)
	}
	if len(got) != 2 || got[0].Name != "GitHub" || got[1].Username != "root" {
		t.Errorf("secrets = %+v", got)
	}

	// Read extras
	gotPw, err := GetExtra[map[string]string](restored, "secretPasswords")
	if err != nil {
		t.Fatalf("GetExtra: %v", err)
	}
	if gotPw["s1"] != "pass1" {
		t.Errorf("password s1 = %q, want pass1", gotPw["s1"])
	}
}

func TestMigration(t *testing.T) {
	// Create a v1 archive (secrets without has_totp)
	a := NewArchive("warden", 1, 0, true)
	secrets := []testSecret{
		{ID: "s1", Name: "GitHub", Username: "admin"},
	}
	if err := SetEntities(a, "secrets", secrets); err != nil {
		t.Fatal(err)
	}

	// Pack and unpack (simulates backup/restore cycle)
	data, _ := Pack(a)
	restored, _ := Unpack(data)

	// Validate
	if err := Validate(restored, "warden", 2); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Set up migration registry: v1 → v2 adds has_totp field
	reg := NewMigrationRegistry("warden")
	reg.Register(1, func(entities map[string]json.RawMessage) error {
		return MigrateAddField(entities, "secrets", "has_totp", false)
	})

	// Run migrations
	applied, err := reg.RunMigrations(restored, 2)
	if err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	if applied != 1 {
		t.Errorf("applied = %d, want 1", applied)
	}
	if restored.Manifest.SchemaVersion != 2 {
		t.Errorf("schemaVersion after migration = %d, want 2", restored.Manifest.SchemaVersion)
	}

	// Read migrated entities — should have has_totp field
	got, err := GetEntities[testSecretV2](restored, "secrets")
	if err != nil {
		t.Fatalf("GetEntities v2: %v", err)
	}
	if len(got) != 1 || got[0].HasTotp != false || got[0].Name != "GitHub" {
		t.Errorf("migrated secret = %+v", got)
	}
}

func TestValidation(t *testing.T) {
	a := NewArchive("warden", 3, 0, true)

	// Wrong module
	if err := Validate(a, "ipam", 3); err == nil {
		t.Error("expected module mismatch error")
	}

	// Version too new
	if err := Validate(a, "warden", 2); err == nil {
		t.Error("expected version too new error")
	}

	// OK
	if err := Validate(a, "warden", 3); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Older version is OK (will need migration)
	if err := Validate(a, "warden", 5); err != nil {
		t.Errorf("unexpected error for older version: %v", err)
	}
}

func TestMissingMigration(t *testing.T) {
	a := NewArchive("warden", 1, 0, true)

	reg := NewMigrationRegistry("warden")
	// Don't register any migrations

	_, err := reg.RunMigrations(a, 3)
	if err == nil {
		t.Error("expected missing migration error")
	}
}

func TestEmptyEntities(t *testing.T) {
	a := NewArchive("test", 1, 0, false)

	// Getting entities that don't exist returns nil
	got, err := GetEntities[testSecret](a, "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}
