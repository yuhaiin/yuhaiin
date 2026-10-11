package goldens

import (
	"embed"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/xen0bit/veepin/internal/capture"
)

//go:embed corpora/*.corpus
var corporaFS embed.FS

// Load reads one committed corpus by name.
//
// It is embedded rather than read from testdata so that a test anywhere in the
// tree — including tests/interop, three directories away — can compare against
// the same bytes without knowing where they live.
func Load(name string) (*capture.Corpus, error) {
	data, err := corporaFS.ReadFile("corpora/" + name + ".corpus")
	if err != nil {
		return nil, fmt.Errorf("goldens: %w", err)
	}
	c, err := capture.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("goldens: %s: %w", name, err)
	}
	return c, nil
}

// Names lists the committed corpora, sorted.
func Names() ([]string, error) {
	entries, err := fs.ReadDir(corporaFS, "corpora")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, strings.TrimSuffix(path.Base(e.Name()), ".corpus"))
	}
	slices.Sort(out)
	return out, nil
}
