package sqldump

import (
	"context"
	"fmt"
)

// Column describes one table column as needed to rebuild a staging table and to
// map data by name on restore.
type Column struct {
	Name string `json:"n"`
	// Type is the fully-rendered Postgres type (e.g. "character varying(255)",
	// "timestamp with time zone", "jsonb", "text[]"), used to build the staging
	// table so COPY text decoding matches.
	Type string `json:"t"`
	// Serial is set when the column is backed by a sequence (serial/identity);
	// such sequences are reset after a restore.
	Serial bool `json:"s,omitempty"`
}

// TableMeta is the per-table metadata stored in the manifest.
type TableMeta struct {
	Name    string   `json:"name"`
	Columns []Column `json:"columns"`
	PK      []string `json:"pk,omitempty"` // primary or unique key columns (empty if none)
}

// colNames returns the ordered column names.
func (t TableMeta) colNames() []string {
	out := make([]string, len(t.Columns))
	for i, c := range t.Columns {
		out[i] = c.Name
	}
	return out
}

// introspect reads live column definitions, the primary (or a unique) key, and
// which columns are sequence-backed, for public.<table>.
func introspect(ctx context.Context, conn querier, table string) (*TableMeta, error) {
	oid, err := tableOID(ctx, conn, table)
	if err != nil {
		return nil, err
	}

	meta := &TableMeta{Name: table}

	rows, err := conn.Query(ctx, `
		SELECT a.attname,
		       pg_catalog.format_type(a.atttypid, a.atttypmod),
		       (pg_get_serial_sequence($1, a.attname) IS NOT NULL) AS is_serial
		FROM pg_attribute a
		WHERE a.attrelid = $2
		  AND a.attnum > 0
		  AND NOT a.attisdropped
		ORDER BY a.attnum`, "public."+table, oid)
	if err != nil {
		return nil, fmt.Errorf("sqldump: columns for %s: %w", table, err)
	}
	for rows.Next() {
		var c Column
		if err := rows.Scan(&c.Name, &c.Type, &c.Serial); err != nil {
			rows.Close()
			return nil, err
		}
		meta.Columns = append(meta.Columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(meta.Columns) == 0 {
		return nil, fmt.Errorf("sqldump: table %s has no columns", table)
	}

	pk, err := keyColumns(ctx, conn, oid)
	if err != nil {
		return nil, err
	}
	meta.PK = pk
	return meta, nil
}

// tableOID resolves public.<table> to its relation OID, or an error if missing.
func tableOID(ctx context.Context, conn querier, table string) (uint32, error) {
	var oid uint32
	err := conn.QueryRow(ctx, `SELECT to_regclass($1)::oid`, "public."+table).Scan(&oid)
	if err != nil {
		return 0, fmt.Errorf("sqldump: resolve table %s: %w", table, err)
	}
	if oid == 0 {
		return 0, fmt.Errorf("sqldump: table %s does not exist", table)
	}
	return oid, nil
}

// keyColumns returns the primary key columns, or a unique (non-partial) key as a
// fallback, or empty if the table has neither.
func keyColumns(ctx context.Context, conn querier, oid uint32) ([]string, error) {
	const q = `
		SELECT a.attname
		FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		WHERE i.indrelid = $1
		  AND i.indisprimary
		ORDER BY array_position(i.indkey, a.attnum)`
	cols, err := scanStrings(ctx, conn, q, oid)
	if err != nil {
		return nil, err
	}
	if len(cols) > 0 {
		return cols, nil
	}
	// Fallback: smallest unique, non-partial, valid index.
	const uq = `
		SELECT a.attname
		FROM pg_index i
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
		WHERE i.indrelid = $1
		  AND i.indisunique
		  AND i.indisvalid
		  AND i.indpred IS NULL
		  AND i.indexprs IS NULL
		  AND i.indexrelid = (
		      SELECT indexrelid FROM pg_index
		      WHERE indrelid = $1 AND indisunique AND indisvalid AND indpred IS NULL AND indexprs IS NULL
		      ORDER BY array_length(indkey, 1) ASC
		      LIMIT 1)
		ORDER BY array_position(i.indkey, a.attnum)`
	return scanStrings(ctx, conn, uq, oid)
}

func scanStrings(ctx context.Context, conn querier, q string, args ...any) ([]string, error) {
	rows, err := conn.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
