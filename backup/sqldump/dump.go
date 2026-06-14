package sqldump

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// querier is satisfied by both *pgx.Conn and pgx.Tx.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Dump streams a self-describing archive of the engine's tables to w. All tables
// are read from a single REPEATABLE READ snapshot, so the dump is internally
// consistent for this module. extras are arbitrary named blobs appended after
// the table data (e.g. Vault secret material for Warden); they may be nil.
func (e *Engine) Dump(ctx context.Context, w io.Writer, extras map[string][]byte) error {
	conn, err := e.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("sqldump: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	manifest := &Manifest{
		Module:    e.opts.Module,
		Format:    archiveFormat,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, t := range e.effectiveTables() {
		meta, err := introspect(ctx, tx, t)
		if err != nil {
			return err
		}
		manifest.Tables = append(manifest.Tables, *meta)
	}
	for name := range extras {
		manifest.Extras = append(manifest.Extras, name)
	}
	sort.Strings(manifest.Extras)

	if err := writeHeader(w, manifest); err != nil {
		return fmt.Errorf("sqldump: write header: %w", err)
	}

	pgConn := tx.Conn().PgConn()
	for _, meta := range manifest.Tables {
		cols := quoteCols(meta.colNames())
		sql := fmt.Sprintf("COPY public.%s (%s) TO STDOUT (FORMAT text)", quoteIdent(meta.Name), cols)
		cw := &chunkWriter{w: w}
		if _, err := pgConn.CopyTo(ctx, cw, sql); err != nil {
			return fmt.Errorf("sqldump: copy out %s: %w", meta.Name, err)
		}
		if err := cw.Close(); err != nil {
			return err
		}
	}

	for _, name := range manifest.Extras {
		if err := writeBlock(w, extras[name]); err != nil {
			return fmt.Errorf("sqldump: write extra %s: %w", name, err)
		}
	}

	return tx.Rollback(ctx) // read-only; nothing to commit
}

// quoteCols quotes and comma-joins a column list.
func quoteCols(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = quoteIdent(c)
	}
	return strings.Join(q, ", ")
}
