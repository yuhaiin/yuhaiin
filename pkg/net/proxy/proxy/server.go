package proxy

import (
	"io"
)

type Server interface {
	io.Closer
}
