// Package backup provides shared types and utilities for the module backup system.
//
// Each module collects its entities, serializes them to JSON, gzip-compresses the
// result, and sends the opaque []byte to the backup server. The backup server
// stores/encrypts without parsing. On restore, the module receives the same bytes,
// decompresses, runs any necessary schema migrations, and upserts entities.
package backup

import (
	"encoding/json"
	"time"
)

// Manifest describes the contents of a backup archive.
// It is embedded inside the gzipped JSON payload so the receiving module can
// verify compatibility and apply migrations.
type Manifest struct {
	Module        string           `json:"module"`
	SchemaVersion int              `json:"schemaVersion"`
	ExportedAt    time.Time        `json:"exportedAt"`
	TenantID      uint32           `json:"tenantId"`
	FullBackup    bool             `json:"fullBackup"`
	EntityCounts  map[string]int64 `json:"entityCounts"`
}

// Archive is the top-level structure inside the gzipped bytes.
//
//	{
//	  "manifest": { ... },
//	  "entities": { "folders": [...], "secrets": [...] },
//	  "extras":   { "secretPasswords": { ... } }
//	}
type Archive struct {
	Manifest Manifest                       `json:"manifest"`
	Entities map[string]json.RawMessage     `json:"entities"`
	Extras   map[string]json.RawMessage     `json:"extras,omitempty"`
}

// NewArchive creates a new empty archive for the given module.
func NewArchive(module string, schemaVersion int, tenantID uint32, fullBackup bool) *Archive {
	return &Archive{
		Manifest: Manifest{
			Module:        module,
			SchemaVersion: schemaVersion,
			ExportedAt:    time.Now().UTC(),
			TenantID:      tenantID,
			FullBackup:    fullBackup,
			EntityCounts:  make(map[string]int64),
		},
		Entities: make(map[string]json.RawMessage),
		Extras:   make(map[string]json.RawMessage),
	}
}

// SetEntities serializes a slice of entities and stores it under the given key.
func SetEntities[T any](a *Archive, key string, entities []T) error {
	raw, err := json.Marshal(entities)
	if err != nil {
		return err
	}
	a.Entities[key] = raw
	a.Manifest.EntityCounts[key] = int64(len(entities))
	return nil
}

// GetEntities deserializes entities from the archive for the given key.
// Returns an empty slice if the key doesn't exist.
func GetEntities[T any](a *Archive, key string) ([]T, error) {
	raw, ok := a.Entities[key]
	if !ok {
		return nil, nil
	}
	var result []T
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// SetExtra stores arbitrary extra data (e.g., Vault passwords) in the archive.
func SetExtra(a *Archive, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	a.Extras[key] = raw
	return nil
}

// GetExtra deserializes extra data from the archive.
func GetExtra[T any](a *Archive, key string) (T, error) {
	var zero T
	raw, ok := a.Extras[key]
	if !ok {
		return zero, nil
	}
	var result T
	if err := json.Unmarshal(raw, &result); err != nil {
		return zero, err
	}
	return result, nil
}
