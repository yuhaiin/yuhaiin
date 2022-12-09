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

type field struct {
	mode   string
	fields map[string]string
}

func rangeRule(path string, ranger func(string, field)) {
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
			fs := bytes.FieldsFunc(fields[1], func(r rune) bool { return r == ',' })
			f := field{
				mode: strings.ToLower(string(fs[0])),
			}

			for _, x := range fs[1:] {
				i := bytes.IndexByte(x, '=')
				if i == -1 {
					continue
				}

				if f.fields == nil {
					f.fields = make(map[string]string)
				}

				f.fields[strings.ToLower(string(x[:i]))] = strings.ToLower(string(x[i:]))
			}

			ranger(strings.ToLower(string(fields[0])), f)
		}
	}
}
