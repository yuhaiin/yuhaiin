package nebula

import (
	"errors"
	"io"
	"log/slog"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
)

// RecoveryFiles resolves the same PKI options as the native protocol without
// constructing its tunnel. Inline PEM is already part of the node document.
func RecoveryFiles(input contract.Nebula) ([]string, error) {
	c, err := parseConfig(input.ConfigYAML, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return nil, err
	}
	files := []string{}
	for _, entry := range []struct{ key, defaultPath string }{{"pki.ca", ""}, {"pki.cert", ""}, {"pki.key", ""}} {
		value := c.GetString(entry.key, entry.defaultPath)
		if value == "" {
			return nil, errors.New("nebula recovery inventory requires explicit PKI inputs")
		}
		if strings.Contains(value, "-----BEGIN") {
			continue
		}
		if strings.HasPrefix(value, "pkcs11:") {
			return nil, errors.New("hardware-backed Nebula keys require an external recovery procedure")
		}
		files = append(files, value)
	}
	return files, nil
}
