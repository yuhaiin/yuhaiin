package main

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"os"
)

//go:generate go run generate.go

//go:embed yuhaiin.conf
var data []byte

func main() {
	b := bytes.NewBuffer(nil)

	gw := gzip.NewWriter(b)
	gw.Write(data)
	gw.Close()

	err := os.WriteFile("bypass.gz", b.Bytes(), 0644)
	if err != nil {
		panic(err)
	}
}
