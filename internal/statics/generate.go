//go:build ignore

package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
)

func main() {
	data, err := os.ReadFile(fmt.Sprintf("%s/Documents/Programming/ACL/yuhaiin/yuhaiin.conf", os.Getenv("HOME")))
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
