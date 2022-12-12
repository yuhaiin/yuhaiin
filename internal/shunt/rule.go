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
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

//go:embed statics/bypass.gz
var BYPASS_DATA []byte

type Field struct {
	mode   bypass.Mode
	Fields map[string]string
}

func (f *Field) Value(key string) (string, bool) {
	if f == nil || f.Fields == nil {
		return "", false
	}

	x, ok := f.Fields[key]
	return x, ok
}

func (m *Field) Mode() bypass.Mode { return m.mode.Mode() }
func (m *Field) Unknown() bool     { return m.mode.Unknown() }

func rangeRule(path string, ranger func(string, bypass.ModeEnum)) {
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
		fields := bytes.Fields(yerror.Ignore2(bytes.Cut(br.Bytes(), []byte{'#'})))
		if len(fields) < 2 {
			continue
		}

		fs := bytes.FieldsFunc(fields[1], func(r rune) bool { return r == ',' })
		f := &Field{
			mode: bypass.Mode(bypass.Mode_value[strings.ToLower(string(fs[0]))]),
		}

		if f.Unknown() {
			continue
		}

		if f.Mode() == bypass.Mode_proxy {
			for _, x := range fs[1:] {
				i := bytes.IndexByte(x, '=')
				if i == -1 {
					continue
				}

				if f.Fields == nil {
					f.Fields = make(map[string]string)
				}

				f.Fields[strings.ToLower(string(x[:i]))] = strings.ToLower(string(x[i+1:]))
			}
		}

		if f.Mode() != bypass.Mode_proxy || len(f.Fields) == 0 {
			ranger(strings.ToLower(string(fields[0])), f.Mode())
		} else {
			ranger(strings.ToLower(string(fields[0])), f)
		}
	}
}
