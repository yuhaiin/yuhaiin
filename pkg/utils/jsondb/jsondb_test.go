package jsondb

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenStrictRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenStrict(path, struct {
		Enabled bool `json:"enabled"`
	}{}); err == nil {
		t.Fatal("OpenStrict accepted malformed JSON")
	}
}

func TestOpenStrictPreservesMissingFileError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	_, err := OpenStrict(path, map[string]string{})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenStrict missing file error = %v", err)
	}
}
