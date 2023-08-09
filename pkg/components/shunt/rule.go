package shunt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Asutorufa/yuhaiin/internal/statics"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func rangeRule(path string, ranger func(string, bypass.ModeEnum)) {
	var reader io.ReadCloser
	var err error
	reader, err = os.Open(path)
	if err != nil {
		log.Error("open bypass file failed, fallback to use internal bypass data", slog.String("filepath", path), slog.Any("err", err))
		reader, _ = gzip.NewReader(bytes.NewReader(statics.BYPASS_DATA))
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

		ranger(strings.ToLower(string(fields[0])), f.ToModeEnum())
	}
}
