package shunt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

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
		f := &bypass.ModeConfig{
			Mode: bypass.Mode(bypass.Mode_value[strings.ToLower(string(fs[0]))]),
		}

		if f.Unknown() {
			continue
		}

		if f.Mode == bypass.Mode_proxy {
			f.StoreKV(fs[1:])
		}

		if f.Mode != bypass.Mode_proxy || len(f.GetTag()) == 0 {
			ranger(strings.ToLower(string(fields[0])), f.Mode)
		} else {
			ranger(strings.ToLower(string(fields[0])), bypass.Tag(f.GetTag()))
		}
	}
}
