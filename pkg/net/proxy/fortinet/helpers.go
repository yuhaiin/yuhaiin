package fortinet

import (
	"fmt"
	"io"
	"os"
)

// logDest is where the CLI-constructed logger writes.
func logDest() io.Writer { return os.Stdout }

// readFile reads a required PEM file, turning an empty path into a clear error.
func readFile(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("no path given")
	}
	return os.ReadFile(path)
}
