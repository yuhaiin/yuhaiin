//go:build !openwrt
// +build !openwrt

package shunt

import (
	_ "embed"
)

//go:embed statics/bypass.gz
var BYPASS_DATA []byte
