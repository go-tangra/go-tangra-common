// Package sqldump provides a schema-agnostic, streaming logical backup/restore
// engine for a module's own PostgreSQL tables. Each module owns the connection
// to the shared database; this engine dumps the module's table set via COPY and
// streams a self-describing archive, and restores it into a running system via a
// temp-staging table plus a dynamically built INSERT ... ON CONFLICT upsert.
//
// Design properties:
//   - Schema-agnostic: columns are discovered live (pg_attribute) at dump time
//     and re-discovered at restore time; new columns get their DEFAULT, dropped
//     columns are skipped. No hand-written per-column code.
//   - Streaming: tables are moved with COPY and framed in fixed-size chunks, so
//     arbitrarily large tables never sit fully in memory.
//   - Live restore: MERGE (upsert) by default; FULL_SYNC additionally deletes
//     rows absent from the backup. FK order is handled with
//     session_replication_role = replica, so no topological sorting is needed.
package sqldump

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RestoreMode selects how a restore reconciles with existing data.
type RestoreMode int

const (
	// RestoreMerge upserts the backup's rows (insert new, update existing) and
	// leaves rows not present in the backup untouched. Safe on a running system.
	RestoreMerge RestoreMode = iota
	// RestoreFullSync upserts the backup's rows and then deletes any row not
	// present in the backup, making the table match the backup exactly.
	RestoreFullSync
)

func (m RestoreMode) String() string {
	if m == RestoreFullSync {
		return "full-sync"
	}
	return "merge"
}

// Options configures an Engine.
type Options struct {
	// Module is a label recorded in the archive manifest (e.g. "ipam").
	Module string
	// Tables is the authoritative, fully-qualified-by-name table list the module
	// owns (typically derived from ent's migrate.Tables). Names are matched
	// against public.<name>.
	Tables []string
	// Exclude lists table names to skip even if present in Tables.
	Exclude []string
}

// Engine dumps and restores a fixed set of tables over its own dedicated
// connection (independent of the module's ORM pool, so COPY is always available
// regardless of the ORM driver).
type Engine struct {
	dsn  string
	opts Options
}

// New builds an Engine. dsn is a standard libpq/pgx connection string
// (postgres://user:pass@host:port/db?...). The caller derives it from its own
// database config.
func New(dsn string, opts Options) *Engine {
	return &Engine{dsn: dsn, opts: opts}
}

// effectiveTables returns Tables minus Exclude, order preserved.
func (e *Engine) effectiveTables() []string {
	if len(e.opts.Exclude) == 0 {
		return e.opts.Tables
	}
	skip := make(map[string]bool, len(e.opts.Exclude))
	for _, t := range e.opts.Exclude {
		skip[t] = true
	}
	out := make([]string, 0, len(e.opts.Tables))
	for _, t := range e.opts.Tables {
		if !skip[t] {
			out = append(out, t)
		}
	}
	return out
}

// connect opens a single dedicated connection for the operation.
func (e *Engine) connect(ctx context.Context) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, e.dsn)
	if err != nil {
		return nil, fmt.Errorf("sqldump: connect: %w", err)
	}
	return conn, nil
}

// quoteIdent safely quotes a SQL identifier.
func quoteIdent(s string) string {
	return pgx.Identifier{s}.Sanitize()
}
