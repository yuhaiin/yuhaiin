package websocket

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"

	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

// A HybiFrameWriter is a writer for hybi frame.
type hybiFrameWriter struct {
	writer         *bufio.Writer
	writeHeaderBuf [8]byte
	header         header
}

func (frame *hybiFrameWriter) Write(msg []byte) (n int, err error) {
	frame.header.payloadLength = int64(len(msg))
	if err = writeFrameHeader(frame.header, frame.writer, frame.writeHeaderBuf[:]); err != nil {
		return 0, err
	}

	if frame.header.masked {
		buf := pool.GetBytesV2(len(msg))
		defer pool.PutBytesV2(buf)

		copy(buf.Bytes(), msg)

		msg = buf.Bytes()
		mask(frame.header.maskKey, msg)
	}

	frame.writer.Write(msg)

	return len(msg), frame.writer.Flush()
}

func (frame *hybiFrameWriter) Close() error { return nil }

type hybiFrameWriterFactory struct {
	*bufio.Writer
	needMaskingKey bool
}

func (buf hybiFrameWriterFactory) NewFrameWriter(payloadType opcode) (frame frameWriter, err error) {
	frameHeader := header{fin: true, opcode: payloadType}
	if buf.needMaskingKey {
		frameHeader.masked = true
		binary.Read(rand.Reader, binary.BigEndian, &frameHeader.maskKey)
	}
	return &hybiFrameWriter{writer: buf.Writer, header: frameHeader}, nil
}
