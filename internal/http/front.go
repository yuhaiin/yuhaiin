//go:build !lite
// +build !lite

package simplehttp

import "embed"

//go:embed all:out
var front embed.FS
