package http

import (
	"bytes"
	"net"
	"net/http"
	"unsafe"
)

var Methods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodPost:    true,
	http.MethodPut:     true,
	http.MethodPatch:   true,
	http.MethodDelete:  true,
	http.MethodConnect: true,
	http.MethodOptions: true,
	http.MethodTrace:   true,
}

func Sniff(b []byte) string {
	tr := &reader{b: b}

	method, _, ok := tr.ReadLine()
	if !ok {
		return ""
	}

	if !Methods[unsafe.String(unsafe.SliceData(method), len(method))] {
		return ""
	}

	for {
		header, host, ok := tr.ReadLine()
		if !ok {
			return ""
		}

		if bytes.Equal(header, []byte("Host:")) {
			h, _, err := net.SplitHostPort(string(host))
			if err == nil {
				return h
			}

			if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
				host = host[1 : len(host)-1]
			}

			return string(host)
		}
	}
}

type reader struct {
	b      []byte
	offset int
}

var cl = []byte("\r\n")

func (r *reader) ReadLine() (key, value []byte, ok bool) {
	i := bytes.Index(r.b[r.offset:], cl)
	if i == -1 {
		return nil, nil, false
	}

	line := r.b[r.offset : r.offset+i]
	r.offset += i + 2

	i = bytes.IndexByte(line, ' ')
	if i == -1 {
		return nil, nil, false
	}

	key = line[:i]
	value = line[i+1:]

	return key, value, true
}
