package paths

import (
	"errors"
	"os"
	"path/filepath"
)

var PathGenerator = pathGenerator{}

type pathGenerator struct{}

func (p pathGenerator) Lock(dir string) string   { return p.makeDir(filepath.Join(dir, "LOCK")) }
func (p pathGenerator) Node(dir string) string   { return p.makeDir(filepath.Join(dir, "node.json")) }
func (p pathGenerator) Config(dir string) string { return p.makeDir(filepath.Join(dir, "config.json")) }
func (p pathGenerator) State(dir string) string  { return p.makeDir(filepath.Join(dir, "state.db")) }
func (p pathGenerator) PebbleCache(dir string) string {
	return p.makeDir(filepath.Join(dir, "pebble_cache"))
}

func (p pathGenerator) Log(dir string) string {
	return p.makeDir(filepath.Join(dir, "log", "yuhaiin.log"))
}

func (pathGenerator) makeDir(s string) string {
	if _, err := os.Stat(s); errors.Is(err, os.ErrNotExist) {
		_ = os.MkdirAll(filepath.Dir(s), os.ModePerm)
	}

	return s
}
