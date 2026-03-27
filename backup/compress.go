package backup

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
)

// Pack serializes the archive to JSON and gzip-compresses it.
// Returns the compressed bytes ready to send to the backup server.
func Pack(a *Archive) ([]byte, error) {
	jsonData, err := json.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("marshal archive: %w", err)
	}

	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("create gzip writer: %w", err)
	}
	if _, err := gz.Write(jsonData); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}

	return buf.Bytes(), nil
}

// Unpack decompresses gzipped bytes and deserializes the archive.
// Does NOT run migrations — call RunMigrations separately after validation.
func Unpack(data []byte) (*Archive, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("create gzip reader: %w", err)
	}
	defer gz.Close()

	jsonData, err := io.ReadAll(gz)
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}

	var a Archive
	if err := json.Unmarshal(jsonData, &a); err != nil {
		return nil, fmt.Errorf("unmarshal archive: %w", err)
	}

	return &a, nil
}
