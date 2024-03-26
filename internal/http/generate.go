//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"os"
	"path"

	"github.com/Asutorufa/yuhaiin/pkg/log"
)

//go:generate go run generate.go

func main() {
	if err := compress("out"); err != nil {
		panic(err)
	}
}

func compress(f string) error {
	dir, err := os.ReadDir(f)
	if err != nil {
		return err
	}

	for _, v := range dir {
		fs := path.Join(f, v.Name())

		if v.IsDir() {
			if err := compress(fs); err != nil {
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
	}

	return nil
}
