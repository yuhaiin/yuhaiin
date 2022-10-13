package shunt

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"os"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

type MODE_MARK_KEY struct{}

func (MODE_MARK_KEY) String() string { return "MODE" }

type DOMAIN_MARK_KEY struct{}

type IP_MARK_KEY struct{}

func (IP_MARK_KEY) String() string { return "IP" }

//go:embed statics/bypass.gz
var BYPASS_DATA []byte

type ForceModeKey struct{}

func getBypassData(path string) io.ReadCloser {
	f, err := os.Open(path)
	if err == nil {
		return f
	}

	log.Errorf("open bypass file %s failed: %v, fallback to use internal bypass data", path, err)

	gr, _ := gzip.NewReader(bytes.NewReader(BYPASS_DATA))
	return gr
}
