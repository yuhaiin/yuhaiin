//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"os"
)

func main() {
	data, err := os.ReadFile("bypass.conf")
	if err != nil {
		panic(err)
	}

	b := bytes.NewBuffer(nil)

	gw := gzip.NewWriter(b)
	gw.Write(data)
	gw.Close()

	err = os.WriteFile("bypass.gz", b.Bytes(), 0644)
	if err != nil {
		panic(err)
	}
}
