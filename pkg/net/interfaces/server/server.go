package server

import (
	"io"
)

type Server interface {
	io.Closer
}
