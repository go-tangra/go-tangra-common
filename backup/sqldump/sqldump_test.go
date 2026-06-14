package sqldump

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

// TestFrameRoundTrip exercises the streaming archive format: header + per-table
// chunked COPY streams (with terminators) + trailing extras, written then read
// back exactly. This is the transport backbone, so it must be byte-exact.
func TestFrameRoundTrip(t *testing.T) {
	manifest := &Manifest{
		Module: "ipam",
		Format: archiveFormat,
		Tables: []TableMeta{
			{Name: "ipam_devices", Columns: []Column{{Name: "id", Type: "text"}, {Name: "name", Type: "text"}}, PK: []string{"id"}},
			{Name: "ipam_big", Columns: []Column{{Name: "id", Type: "bigint", Serial: true}}, PK: []string{"id"}},
		},
		Extras: []string{"secretPasswords"},
	}
	// Distinct payloads, including one larger than a single Write to exercise
	// multi-chunk framing.
	devicesData := []byte("id1\tdev-one\nid2\tdev-two\n")
	bigData := bytes.Repeat([]byte("0123456789"), 5000) // 50 KB
	extraData := []byte(`{"sec-1":"p@ss"}`)

	var buf bytes.Buffer
	if err := writeHeader(&buf, manifest); err != nil {
		t.Fatalf("writeHeader: %v", err)
	}
	// table 1
	cw := &chunkWriter{w: &buf}
	if _, err := cw.Write(devicesData); err != nil {
		t.Fatal(err)
	}
	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}
	// table 2 — write in several Writes
	cw = &chunkWriter{w: &buf}
	for i := 0; i < len(bigData); i += 7000 {
		end := i + 7000
		if end > len(bigData) {
			end = len(bigData)
		}
		if _, err := cw.Write(bigData[i:end]); err != nil {
			t.Fatal(err)
		}
	}
	if err := cw.Close(); err != nil {
		t.Fatal(err)
	}
	// extra
	if err := writeBlock(&buf, extraData); err != nil {
		t.Fatal(err)
	}

	// --- read back ---
	r := bytes.NewReader(buf.Bytes())
	gotManifest, err := readHeader(r)
	if err != nil {
		t.Fatalf("readHeader: %v", err)
	}
	if !reflect.DeepEqual(gotManifest, manifest) {
		t.Fatalf("manifest mismatch:\n got %+v\nwant %+v", gotManifest, manifest)
	}

	got1, err := io.ReadAll(&chunkReader{r: r})
	if err != nil {
		t.Fatalf("read table1: %v", err)
	}
	if !bytes.Equal(got1, devicesData) {
		t.Fatalf("table1 data mismatch: got %q", got1)
	}

	got2, err := io.ReadAll(&chunkReader{r: r})
	if err != nil {
		t.Fatalf("read table2: %v", err)
	}
	if !bytes.Equal(got2, bigData) {
		t.Fatalf("table2 data mismatch: len got %d want %d", len(got2), len(bigData))
	}

	gotExtra, err := readBlock(r)
	if err != nil {
		t.Fatalf("read extra: %v", err)
	}
	if !bytes.Equal(gotExtra, extraData) {
		t.Fatalf("extra mismatch: got %q", gotExtra)
	}
}

// TestChunkReaderDrain verifies a skipped table's stream is consumed up to its
// terminator so the next table aligns.
func TestChunkReaderDrain(t *testing.T) {
	var buf bytes.Buffer
	cw := &chunkWriter{w: &buf}
	_, _ = cw.Write([]byte("some-rows"))
	_ = cw.Close()
	_ = writeBlock(&buf, []byte("after"))

	r := bytes.NewReader(buf.Bytes())
	if err := (&chunkReader{r: r}).drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	after, err := readBlock(r)
	if err != nil || string(after) != "after" {
		t.Fatalf("post-drain alignment broken: %q %v", after, err)
	}
}

func TestSetHelpers(t *testing.T) {
	if got := intersect([]string{"a", "b", "c"}, []string{"b", "c", "d"}); !reflect.DeepEqual(got, []string{"b", "c"}) {
		t.Fatalf("intersect: %v", got)
	}
	if got := diff([]string{"a", "b", "c"}, []string{"b"}); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("diff: %v", got)
	}
	if got := filterPresent([]string{"id", "x"}, []string{"id", "name"}); !reflect.DeepEqual(got, []string{"id"}) {
		t.Fatalf("filterPresent: %v", got)
	}
}

func TestAssignExcluded(t *testing.T) {
	if got := assignExcluded(nil); got != "" {
		t.Fatalf("empty: %q", got)
	}
	got := assignExcluded([]string{"name", "cidr"})
	want := `"name" = EXCLUDED."name", "cidr" = EXCLUDED."cidr"`
	if got != want {
		t.Fatalf("assignExcluded:\n got %s\nwant %s", got, want)
	}
}

func TestEffectiveTablesExclude(t *testing.T) {
	e := New("", Options{Tables: []string{"a", "b", "c"}, Exclude: []string{"b"}})
	if got := e.effectiveTables(); !reflect.DeepEqual(got, []string{"a", "c"}) {
		t.Fatalf("effectiveTables: %v", got)
	}
}
