//go:build !lite
// +build !lite

package shunt

import (
	_ "embed"
)

//go:embed statics/bypass.gz
var BYPASS_DATA []byte
