package backup

import "fmt"

// RestoreMode determines how existing entities are handled during import.
type RestoreMode int

const (
	RestoreModeSkip      RestoreMode = 0 // Skip existing entities
	RestoreModeOverwrite RestoreMode = 1 // Overwrite existing entities
)

// EntityResult tracks import statistics for a single entity type.
type EntityResult struct {
	EntityType string `json:"entityType"`
	Total      int64  `json:"total"`
	Created    int64  `json:"created"`
	Updated    int64  `json:"updated"`
	Skipped    int64  `json:"skipped"`
	Failed     int64  `json:"failed"`
}

// RestoreResult is the overall result of an import operation.
type RestoreResult struct {
	Success           bool           `json:"success"`
	Results           []EntityResult `json:"results"`
	Warnings          []string       `json:"warnings"`
	SourceVersion     int            `json:"sourceVersion"`
	TargetVersion     int            `json:"targetVersion"`
	MigrationsApplied int            `json:"migrationsApplied"`
}

// NewRestoreResult creates an empty result initialized for the given versions.
func NewRestoreResult(sourceVersion, targetVersion, migrationsApplied int) *RestoreResult {
	return &RestoreResult{
		Success:           true,
		SourceVersion:     sourceVersion,
		TargetVersion:     targetVersion,
		MigrationsApplied: migrationsApplied,
	}
}

// AddResult appends an entity import result.
func (r *RestoreResult) AddResult(er EntityResult) {
	r.Results = append(r.Results, er)
	if er.Failed > 0 {
		r.Success = false
	}
}

// AddWarning appends a non-fatal warning message.
func (r *RestoreResult) AddWarning(msg string) {
	r.Warnings = append(r.Warnings, msg)
}

// Validate checks that the archive is compatible with the expected module.
// Returns an error if the module name doesn't match or the version is too new.
func Validate(a *Archive, expectedModule string, currentVersion int) error {
	if a.Manifest.Module != expectedModule {
		return fmt.Errorf("module mismatch: expected %q, got %q", expectedModule, a.Manifest.Module)
	}
	if a.Manifest.SchemaVersion > currentVersion {
		return fmt.Errorf("backup version %d is newer than current version %d — upgrade the module first",
			a.Manifest.SchemaVersion, currentVersion)
	}
	if a.Manifest.SchemaVersion < 1 {
		return fmt.Errorf("invalid schema version: %d", a.Manifest.SchemaVersion)
	}
	return nil
}
