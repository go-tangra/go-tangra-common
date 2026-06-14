package sqldump

// archiveFormat identifies the on-the-wire archive layout/version.
const archiveFormat = "copy-text-v1"

// Manifest is the JSON header of a dump archive. It is followed by one framed
// data block per table (in Tables order) and one framed block per extra (in
// Extras order).
type Manifest struct {
	Module    string      `json:"module,omitempty"`
	Format    string      `json:"format"`
	CreatedAt string      `json:"createdAt,omitempty"` // RFC3339, stamped by the caller
	Tables    []TableMeta `json:"tables"`
	Extras    []string    `json:"extras,omitempty"`
}
