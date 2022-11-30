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
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
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
	for br.Scan() {
		if fields := bytes.Fields(yerror.Ignore2(bytes.Cut(br.Bytes(), []byte{'#'}))); len(fields) >= 2 {
			ranger(strings.ToLower(string(fields[0])), strings.ToLower(string(fields[1])))
		}
	}
}
