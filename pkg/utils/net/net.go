package net

import "io"

type nopWriteCloser struct {
	io.Writer
}

func NopWriteCloser(w io.Writer) io.WriteCloser { return &nopWriteCloser{w} }
func (w *nopWriteCloser) Close() error          { return nil }
