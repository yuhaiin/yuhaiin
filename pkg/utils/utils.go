package utils

import (
	_ "net/url"
	_ "unsafe"
)

//go:linkname GetScheme net/url.getScheme
func GetScheme(ur string) (scheme, etc string, err error)
