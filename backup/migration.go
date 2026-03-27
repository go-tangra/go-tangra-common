package backup

import (
	"encoding/json"
	"fmt"
)

// MigrateFunc transforms entity data from version N to version N+1.
// It receives the full entities map and can modify it in place.
// This allows adding/removing/renaming fields, adding default values
// for new fields, or restructuring entity relationships.
type MigrateFunc func(entities map[string]json.RawMessage) error

// MigrationRegistry holds versioned migration functions for a module.
// Migrations are keyed by the SOURCE version they migrate FROM.
// For example, migrations[1] migrates v1 → v2.
type MigrationRegistry struct {
	module     string
	migrations map[int]MigrateFunc
}

// NewMigrationRegistry creates a new registry for the given module.
func NewMigrationRegistry(module string) *MigrationRegistry {
	return &MigrationRegistry{
		module:     module,
		migrations: make(map[int]MigrateFunc),
	}
}

// Register adds a migration function that upgrades from sourceVersion to sourceVersion+1.
func (r *MigrationRegistry) Register(sourceVersion int, fn MigrateFunc) {
	r.migrations[sourceVersion] = fn
}

// RunMigrations applies all necessary migrations to bring the archive from its
// current schema version up to targetVersion. Migrations are applied sequentially.
//
// Returns the number of migrations applied. If no migrations are needed (versions
// match), returns 0 and nil error.
func (r *MigrationRegistry) RunMigrations(a *Archive, targetVersion int) (int, error) {
	if a.Manifest.Module != r.module {
		return 0, fmt.Errorf("module mismatch: archive is %q, registry is %q", a.Manifest.Module, r.module)
	}

	sourceVersion := a.Manifest.SchemaVersion
	if sourceVersion == targetVersion {
		return 0, nil
	}

	if sourceVersion > targetVersion {
		return 0, fmt.Errorf("cannot downgrade: archive version %d > target version %d", sourceVersion, targetVersion)
	}

	applied := 0
	for v := sourceVersion; v < targetVersion; v++ {
		fn, ok := r.migrations[v]
		if !ok {
			return applied, fmt.Errorf("missing migration from v%d to v%d for module %s", v, v+1, r.module)
		}
		if err := fn(a.Entities); err != nil {
			return applied, fmt.Errorf("migration v%d→v%d failed: %w", v, v+1, err)
		}
		applied++
		a.Manifest.SchemaVersion = v + 1
	}

	return applied, nil
}

// MigrateAddField is a convenience helper that adds a field with a default value
// to all items in an entity array. Useful for simple "add new column" migrations.
func MigrateAddField(entities map[string]json.RawMessage, entityKey, fieldName string, defaultValue any) error {
	raw, ok := entities[entityKey]
	if !ok {
		return nil // entity type not in backup, skip
	}

	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("unmarshal %s: %w", entityKey, err)
	}

	for i := range items {
		if _, exists := items[i][fieldName]; !exists {
			items[i][fieldName] = defaultValue
		}
	}

	updated, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", entityKey, err)
	}
	entities[entityKey] = updated
	return nil
}

// MigrateRenameField renames a field across all items in an entity array.
func MigrateRenameField(entities map[string]json.RawMessage, entityKey, oldName, newName string) error {
	raw, ok := entities[entityKey]
	if !ok {
		return nil
	}

	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("unmarshal %s: %w", entityKey, err)
	}

	for i := range items {
		if val, exists := items[i][oldName]; exists {
			items[i][newName] = val
			delete(items[i], oldName)
		}
	}

	updated, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", entityKey, err)
	}
	entities[entityKey] = updated
	return nil
}

// MigrateRemoveField removes a field from all items in an entity array.
func MigrateRemoveField(entities map[string]json.RawMessage, entityKey, fieldName string) error {
	raw, ok := entities[entityKey]
	if !ok {
		return nil
	}

	var items []map[string]any
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("unmarshal %s: %w", entityKey, err)
	}

	for i := range items {
		delete(items[i], fieldName)
	}

	updated, err := json.Marshal(items)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", entityKey, err)
	}
	entities[entityKey] = updated
	return nil
}
