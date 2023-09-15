//go:build page
// +build page

package statics

import (
	_ "embed"
)

//go:embed bypass.gz
var BYPASS_DATA []byte

//go:generate go run generate.go
