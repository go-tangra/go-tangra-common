package sqldump

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// magic prefixes every archive so a reader can sanity-check the stream.
var magic = [8]byte{'T', 'N', 'G', 'S', 'Q', 'L', 'D', '1'}

// maxBlock caps a single framed block (manifest / extra) to guard against a
// corrupt length driving a huge allocation. Table data is chunked, not capped.
const maxBlock = 256 << 20 // 256 MiB

// writeHeader writes the magic and the length-prefixed manifest JSON.
func writeHeader(w io.Writer, m *Manifest) error {
	if _, err := w.Write(magic[:]); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeBlock(w, b)
}

// readHeader validates the magic and decodes the manifest.
func readHeader(r io.Reader) (*Manifest, error) {
	var got [8]byte
	if _, err := io.ReadFull(r, got[:]); err != nil {
		return nil, fmt.Errorf("sqldump: read magic: %w", err)
	}
	if got != magic {
		return nil, fmt.Errorf("sqldump: bad archive magic")
	}
	b, err := readBlock(r)
	if err != nil {
		return nil, fmt.Errorf("sqldump: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("sqldump: decode manifest: %w", err)
	}
	return &m, nil
}

// writeBlock writes a single length-prefixed block.
func writeBlock(w io.Writer, b []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// readBlock reads a single length-prefixed block.
func readBlock(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n > maxBlock {
		return nil, fmt.Errorf("sqldump: block too large (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// chunkWriter frames each Write as [u32 len][data]; Close writes a zero-length
// terminator marking the end of a table's COPY stream. Used as the destination
// of pgConn.CopyTo.
type chunkWriter struct {
	w io.Writer
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := binary.Write(c.w, binary.BigEndian, uint32(len(p))); err != nil {
		return 0, err
	}
	if _, err := c.w.Write(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close writes the zero-length terminator.
func (c *chunkWriter) Close() error {
	return binary.Write(c.w, binary.BigEndian, uint32(0))
}

// chunkReader reconstructs a single table's COPY stream from framed chunks,
// presenting io.EOF at the zero-length terminator. Used as the source of
// pgConn.CopyFrom.
type chunkReader struct {
	r   io.Reader
	buf []byte
	eof bool
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.buf) == 0 {
		if c.eof {
			return 0, io.EOF
		}
		var n uint32
		if err := binary.Read(c.r, binary.BigEndian, &n); err != nil {
			return 0, err
		}
		if n == 0 {
			c.eof = true
			return 0, io.EOF
		}
		if n > maxBlock {
			return 0, fmt.Errorf("sqldump: chunk too large (%d bytes)", n)
		}
		c.buf = make([]byte, n)
		if _, err := io.ReadFull(c.r, c.buf); err != nil {
			return 0, err
		}
	}
	k := copy(p, c.buf)
	c.buf = c.buf[k:]
	return k, nil
}

// drain consumes any unread chunks of the current table (used when a table is
// skipped on restore) up to and including the terminator.
func (c *chunkReader) drain() error {
	buf := make([]byte, 32*1024)
	for {
		_, err := c.Read(buf)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
