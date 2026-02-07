package audit

import (
	"context"
)

// AuditLogRepository defines the interface for audit log persistence
// Each module should implement this interface in their data layer
type AuditLogRepository interface {
	// CreateFromEntry creates an audit log entry in the database
	CreateFromEntry(ctx context.Context, entry *AuditLogEntry) error
}

// NewDatabaseWriter creates a WriteAuditLogFunc that writes to a database via repository
func NewDatabaseWriter(repo AuditLogRepository) WriteAuditLogFunc {
	return func(ctx context.Context, log *AuditLog) error {
		if repo == nil {
			return nil
		}

		entry := log.ToEntry()
		return repo.CreateFromEntry(ctx, entry)
	}
}

// CombinedWriter combines multiple WriteAuditLogFunc into one
func CombinedWriter(writers ...WriteAuditLogFunc) WriteAuditLogFunc {
	return func(ctx context.Context, log *AuditLog) error {
		var lastErr error
		for _, w := range writers {
			if w != nil {
				if err := w(ctx, log); err != nil {
					lastErr = err
				}
			}
		}
		return lastErr
	}
}

// LoggingWriter creates a WriteAuditLogFunc that only logs to the standard logger
// This is useful for modules that don't need database persistence
func LoggingWriter() WriteAuditLogFunc {
	return func(ctx context.Context, log *AuditLog) error {
		// No-op, the middleware already logs when no writer is provided
		return nil
	}
}
