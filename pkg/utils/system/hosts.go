package system

import (
	_ "net"
	_ "unsafe"
)

//go:linkname LookupStaticHost net.lookupStaticHost
func LookupStaticHost(host string) ([]string, string)

//go:linkname LookupStaticAddr net.lookupStaticAddr
func LookupStaticAddr(addr string) []string
