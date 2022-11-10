package shunt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"os"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

//go:embed statics/bypass.gz
var BYPASS_DATA []byte

func rangeRule(path string, ranger func(string, string)) {
	var reader io.ReadCloser
	var err error
	reader, err = os.Open(path)
	if err != nil {
		log.Errorf("open bypass file %s failed: %v, fallback to use internal bypass data", path, err)

		reader, _ = gzip.NewReader(bytes.NewReader(BYPASS_DATA))
	}

	defer reader.Close()

	br := bufio.NewScanner(reader)
	for {
		if !br.Scan() {
			break
		}

		a := br.Bytes()

		i := bytes.IndexByte(a, '#')
		if i != -1 {
			a = a[:i]
		}

		i = bytes.IndexByte(a, ' ')
		if i == -1 {
			continue
		}

		c, b := a[:i], a[i+1:]

		if len(c) != 0 && len(b) != 0 {
			ranger(strings.ToLower(string(c)), strings.ToLower(string(b)))
		}
	}
}
