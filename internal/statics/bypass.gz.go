//go:build !lite
// +build !lite

package statics

import (
	_ "embed"
)

//go:embed bypass.gz
var BYPASS_DATA []byte
