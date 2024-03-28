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
		log.Error("open bypass file failed, fallback to use internal bypass data",
			slog.String("filepath", path), slog.Any("err", err))

		if len(statics.BYPASS_DATA) == 0 {
			return
		}

		reader, err = gzip.NewReader(bytes.NewReader(statics.BYPASS_DATA))
		if err != nil {
			return
		}
	}
	defer reader.Close()

	br := bufio.NewScanner(reader)

	for br.Scan() {
		fields := bytes.Fields(yerror.Ignore2(bytes.Cut(br.Bytes(), []byte{'#'})))
		if len(fields) < 2 {
			continue
		}

		hostname := strings.ToLower(string(fields[0]))
		args := fields[1]

		fs := bytes.FieldsFunc(args, func(r rune) bool {
			return r == ','
		})

		if len(fs) < 1 {
			continue
		}

		modestr := strings.ToLower(string(fs[0]))

		mode := bypass.Mode(bypass.Mode_value[modestr])

		if mode.Unknown() {
			continue
		}

		f := &bypass.ModeConfig{Mode: mode}
		f.StoreKV(fs[1:])
		ranger(hostname, f.ToModeEnum())
	}
}
