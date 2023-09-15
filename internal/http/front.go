//go:build page
// +build page

package simplehttp

import "embed"

//go:embed all:out
var front embed.FS
