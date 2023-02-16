package websocket

import (
	"bufio"
	"io"
)

// A hybiFrameReader is a reader for hybi frame.
type hybiFrameReader struct {
	reader io.Reader

	header header
}

func (frame *hybiFrameReader) Read(msg []byte) (n int, err error) {
	n, err = frame.reader.Read(msg)
	if frame.header.masked {
		frame.header.maskKey = mask(frame.header.maskKey, msg[:n])
	}
	return n, err
}

func (frame *hybiFrameReader) Header() *header { return &frame.header }

// A hybiFrameReaderFactory creates new frame reader based on its frame type.
type hybiFrameReaderFactory struct {
	*bufio.Reader
	readHeaderBuf [8]byte
}

// NewFrameReader reads a frame header from the connection, and creates new reader for the frame.
// See Section 5.2 Base Framing protocol for detail.
// http://tools.ietf.org/html/draft-ietf-hybi-thewebsocketprotocol-17#section-5.2
func (buf hybiFrameReaderFactory) NewFrameReader() (frameReader, error) {
	header, err := readFrameHeader(buf.Reader, buf.readHeaderBuf[:])

	return &hybiFrameReader{
		header: header,
		reader: io.LimitReader(buf.Reader, header.payloadLength),
	}, err
}
