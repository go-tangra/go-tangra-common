package sqldump

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TableResult reports what happened to one table during a restore.
type TableResult struct {
	Table   string
	Rows    int64  // rows upserted from the backup (insert+update)
	Deleted int64  // rows removed (full-sync only)
	Skipped bool   // table not applied
	Note    string // warning/skip reason
}

// Result summarizes a restore.
type Result struct {
	Mode     string
	Tables   []TableResult
	Warnings []string
}

// Restore reads an archive from r and applies it to the database. It runs in a
// single transaction with session_replication_role = replica so foreign-key and
// trigger ordering is irrelevant. The returned extras map carries the archive's
// named extra blobs (e.g. Vault secret material) for the caller to apply.
func (e *Engine) Restore(ctx context.Context, r io.Reader, mode RestoreMode) (*Result, map[string][]byte, error) {
	manifest, err := readHeader(r)
	if err != nil {
		return nil, nil, err
	}

	conn, err := e.connect(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("sqldump: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Defer FK + user triggers for the duration of the load (tx-scoped).
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		return nil, nil, fmt.Errorf("sqldump: defer constraints (needs elevated role): %w", err)
	}

	res := &Result{Mode: mode.String()}
	pgConn := tx.Conn().PgConn()

	for _, tm := range manifest.Tables {
		tr, err := e.restoreTable(ctx, tx, pgConn, r, tm, mode)
		if err != nil {
			return nil, nil, err
		}
		res.Tables = append(res.Tables, tr)
		if tr.Note != "" {
			res.Warnings = append(res.Warnings, tm.Name+": "+tr.Note)
		}
	}

	extras := make(map[string][]byte, len(manifest.Extras))
	for _, name := range manifest.Extras {
		b, err := readBlock(r)
		if err != nil {
			return nil, nil, fmt.Errorf("sqldump: read extra %s: %w", name, err)
		}
		extras[name] = b
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("sqldump: commit: %w", err)
	}
	return res, extras, nil
}

// restoreTable loads one table's framed COPY stream into a staging table and
// merges it into the live table.
func (e *Engine) restoreTable(ctx context.Context, tx pgx.Tx, pgConn *pgconn.PgConn, r io.Reader, tm TableMeta, mode RestoreMode) (TableResult, error) {
	tr := TableResult{Table: tm.Name}
	cr := &chunkReader{r: r}

	live, err := introspect(ctx, tx, tm.Name)
	if err != nil {
		// Target lacks this table — consume its stream and skip.
		tr.Skipped = true
		tr.Note = "not present on target; skipped"
		return tr, cr.drain()
	}

	// Build a staging table matching the dumped columns/types exactly.
	stg := "_sqldump_stg"
	if _, err := tx.Exec(ctx, "DROP TABLE IF EXISTS "+stg); err != nil {
		return tr, err
	}
	var defs []string
	for _, c := range tm.Columns {
		defs = append(defs, quoteIdent(c.Name)+" "+c.Type)
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf("CREATE TEMP TABLE %s (%s) ON COMMIT DROP", stg, strings.Join(defs, ", "))); err != nil {
		return tr, fmt.Errorf("sqldump: create staging for %s: %w", tm.Name, err)
	}

	loadSQL := fmt.Sprintf("COPY %s (%s) FROM STDIN (FORMAT text)", stg, quoteCols(tm.colNames()))
	if _, err := pgConn.CopyFrom(ctx, cr, loadSQL); err != nil {
		return tr, fmt.Errorf("sqldump: copy into staging %s: %w", tm.Name, err)
	}

	// Columns present in BOTH the dump and the live table (drift-safe).
	cols := intersect(tm.colNames(), live.colNames())
	if len(cols) == 0 {
		tr.Skipped = true
		tr.Note = "no overlapping columns; skipped"
		return tr, dropStaging(ctx, tx, stg)
	}
	pk := filterPresent(live.PK, cols)

	tr, err = e.merge(ctx, tx, tm.Name, stg, cols, pk, mode, tr)
	if err != nil {
		return tr, err
	}
	if err := resetSequences(ctx, tx, tm.Name, live); err != nil {
		return tr, err
	}
	return tr, dropStaging(ctx, tx, stg)
}

// merge applies the staging rows to the live table per mode.
func (e *Engine) merge(ctx context.Context, tx pgx.Tx, table, stg string, cols, pk []string, mode RestoreMode, tr TableResult) (TableResult, error) {
	tbl := "public." + quoteIdent(table)
	colList := quoteCols(cols)

	if len(pk) == 0 {
		// No usable key: safe upsert is impossible.
		if mode == RestoreFullSync {
			if _, err := tx.Exec(ctx, "TRUNCATE "+tbl); err != nil {
				return tr, err
			}
			tag, err := tx.Exec(ctx, fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s", tbl, colList, colList, stg))
			if err != nil {
				return tr, err
			}
			tr.Rows = tag.RowsAffected()
			return tr, nil
		}
		tr.Skipped = true
		tr.Note = "no primary/unique key; cannot merge (use full-sync)"
		return tr, nil
	}

	pkList := quoteCols(pk)
	var sql string
	if setList := assignExcluded(diff(cols, pk)); setList == "" {
		sql = fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s ON CONFLICT (%s) DO NOTHING", tbl, colList, colList, stg, pkList)
	} else {
		sql = fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s ON CONFLICT (%s) DO UPDATE SET %s", tbl, colList, colList, stg, pkList, setList)
	}
	tag, err := tx.Exec(ctx, sql)
	if err != nil {
		return tr, fmt.Errorf("sqldump: upsert %s: %w", table, err)
	}
	tr.Rows = tag.RowsAffected()

	if mode == RestoreFullSync {
		pkTuple := "(" + pkList + ")"
		del := fmt.Sprintf("DELETE FROM %s WHERE %s NOT IN (SELECT %s FROM %s)", tbl, pkTuple, pkList, stg)
		dtag, err := tx.Exec(ctx, del)
		if err != nil {
			return tr, fmt.Errorf("sqldump: full-sync delete %s: %w", table, err)
		}
		tr.Deleted = dtag.RowsAffected()
	}
	return tr, nil
}

// resetSequences advances each sequence-backed column's sequence past the max
// value now present, so future inserts don't collide with restored rows.
func resetSequences(ctx context.Context, tx pgx.Tx, table string, live *TableMeta) error {
	for _, c := range live.Columns {
		if !c.Serial {
			continue
		}
		q := fmt.Sprintf(
			"SELECT setval(pg_get_serial_sequence($1, $2), GREATEST(COALESCE((SELECT MAX(%s) FROM public.%s), 0), 1))",
			quoteIdent(c.Name), quoteIdent(table))
		if _, err := tx.Exec(ctx, q, table, c.Name); err != nil {
			return fmt.Errorf("sqldump: reset sequence %s.%s: %w", table, c.Name, err)
		}
	}
	return nil
}

func dropStaging(ctx context.Context, tx pgx.Tx, stg string) error {
	_, err := tx.Exec(ctx, "DROP TABLE IF EXISTS "+stg)
	return err
}

// --- small set helpers -----------------------------------------------------

func intersect(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, x := range b {
		set[x] = true
	}
	var out []string
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

func diff(a, remove []string) []string {
	set := make(map[string]bool, len(remove))
	for _, x := range remove {
		set[x] = true
	}
	var out []string
	for _, x := range a {
		if !set[x] {
			out = append(out, x)
		}
	}
	return out
}

func filterPresent(want, have []string) []string {
	set := make(map[string]bool, len(have))
	for _, x := range have {
		set[x] = true
	}
	var out []string
	for _, x := range want {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

func assignExcluded(cols []string) string {
	if len(cols) == 0 {
		return ""
	}
	parts := make([]string, len(cols))
	for i, c := range cols {
		q := quoteIdent(c)
		parts[i] = q + " = EXCLUDED." + q
	}
	return strings.Join(parts, ", ")
}
