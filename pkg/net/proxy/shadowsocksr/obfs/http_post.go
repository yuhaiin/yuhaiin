package obfs

import (
	"math/rand/v2"
	"net"
)

// newHttpPost create a http_post object
func newHttpPost(con net.Conn, info Obfs) net.Conn {
	// newHttpSimple create a http_simple object

	t := &httpSimplePost{
		userAgentIndex: rand.IntN(len(requestUserAgent)),
		methodGet:      false,
		Conn:           con,
		Obfs:           info,
	}
	return t
}
