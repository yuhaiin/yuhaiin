package simplehttp

import (
	"bytes"
	"compress/gzip"
	"os"
	"path"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/utils/assert"
)

func TestXxx(t *testing.T) {
	assert.NoError(t, OpenDir("build"))
}

func OpenDir(f string) error {
	dir, err := os.ReadDir(f)
	if err != nil {
		return err
	}

	for _, v := range dir {
		fs := path.Join(f, v.Name())

		if v.IsDir() {
			if err := OpenDir(fs); err != nil {
				log.Error("open dir failed", "err", err)
			}
			continue
		}

		fi, err := v.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(fs)
		if err != nil {
			return err
		}

		var buf bytes.Buffer

		gz := gzip.NewWriter(&buf)

		if _, err := gz.Write(data); err != nil {
			return err
		}
		gz.Close()

		os.Remove(fs)

		if err := os.WriteFile(fs, buf.Bytes(), fi.Mode()); err != nil {
			return err
		}

		// if strings.HasSuffix(v.Name(), ".gz") {
		// os.Remove(strings.TrimSuffix(fs, ".gz"))
		// }

	}

	return nil
}
