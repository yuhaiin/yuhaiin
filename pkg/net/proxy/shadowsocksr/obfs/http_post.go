package obfs

import (
	"math/rand"
	"net"
)

// newHttpPost create a http_post object
func newHttpPost(con net.Conn, info Info) Obfs {
	// newHttpSimple create a http_simple object

	t := &httpSimplePost{
		userAgentIndex: rand.Intn(len(requestUserAgent)),
		methodGet:      false,
		Conn:           con,
		Info:           info,
	}
	return t
}
