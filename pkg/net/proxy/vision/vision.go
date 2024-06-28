package vision

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"math/big"
	"net"
	"reflect"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	utls "github.com/refraction-networking/utls"
)

var (
	tls13SupportedVersions  = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsClientHandShakeStart = []byte{0x16, 0x03}
	tlsServerHandShakeStart = []byte{0x16, 0x03, 0x03}
	tlsApplicationDataStart = []byte{0x17, 0x03, 0x03}
)

const (
	commandPaddingContinue byte = iota
	commandPaddingEnd
	commandPaddingDirect
)

var tls13CipherSuiteDic = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0x1304: "TLS_AES_128_CCM_SHA256",
	0x1305: "TLS_AES_128_CCM_8_SHA256",
}

func reshapeBuffer(b []byte) [][]byte {
	const bufferLimit = 8192 - 21
	if len(b) < bufferLimit {
		return [][]byte{b}
	}
	index := int32(bytes.LastIndex(b, tlsApplicationDataStart))
	if index <= 0 {
		index = 8192 / 2
	}

	return [][]byte{b[:index], b[index:]}
}

const xrayChunkSize = 8192

type VisionConn struct {
	net.Conn
	writer  net.Conn
	netConn net.Conn

	remainingReader        io.Reader
	reader                 *bufio.Reader
	input                  *bytes.Reader
	rawInput               *bytes.Buffer
	numberOfPacketToFilter int
	remainingContent       int
	remainingPadding       int
	remainingServerHello   int32
	cipher                 uint16

	userUUID             [16]byte
	isTLS                bool
	isTLS12orAbove       bool
	enableXTLS           bool
	isPadding            bool
	directWrite          bool
	writeUUID            bool
	withinPaddingBuffers bool
	currentCommand       byte
	directRead           bool
}

func NewVisionConn(conn net.Conn, tlsConn net.Conn, userUUID [16]byte) (*VisionConn, error) {
	var (
		reflectType    reflect.Type
		reflectPointer unsafe.Pointer
		netConn        net.Conn
	)

	switch underlying := tlsConn.(type) {
	case *tls.Conn:
		netConn = underlying.NetConn()
		reflectType = reflect.TypeOf(underlying).Elem()
		reflectPointer = unsafe.Pointer(underlying)
	case *utls.UConn:
		netConn = underlying.NetConn()
		reflectType = reflect.TypeOf(underlying.Conn).Elem()
		reflectPointer = unsafe.Pointer(underlying.Conn)
	default:
		return nil, fmt.Errorf(`failed to use vision, maybe "security" is not "tls" or "utls"`)
	}

	input, _ := reflectType.FieldByName("input")
	rawInput, _ := reflectType.FieldByName("rawInput")

	return &VisionConn{
		Conn:     conn,
		reader:   bufio.NewReaderSize(conn, xrayChunkSize),
		writer:   conn,
		input:    (*bytes.Reader)(unsafe.Add(reflectPointer, input.Offset)),
		rawInput: (*bytes.Buffer)(unsafe.Add(reflectPointer, rawInput.Offset)),
		netConn:  netConn,

		userUUID:               userUUID,
		numberOfPacketToFilter: 8,
		remainingServerHello:   -1,
		isPadding:              true,
		writeUUID:              true,
		withinPaddingBuffers:   true,
		remainingContent:       -1,
		remainingPadding:       -1,
	}, nil
}

func (c *VisionConn) Read(p []byte) (n int, err error) {
	if c.remainingReader != nil {
		n, err = c.remainingReader.Read(p)
		if err == io.EOF {
			err = nil
			c.remainingReader = nil
		}
		if n > 0 {
			return
		}
	}

	if c.directRead {
		return c.netConn.Read(p)
	}

	var bufferBytes []byte
	var chunkBuffer []byte
	if len(p) > xrayChunkSize {
		n, err = c.Conn.Read(p)
		if err != nil {
			return
		}
		bufferBytes = p[:n]
	} else {
		buf := make([]byte, xrayChunkSize)
		n, err = c.reader.Read(buf)
		if err != nil {
			return 0, err
		}
		chunkBuffer = buf[:n]
		bufferBytes = chunkBuffer
	}
	if c.withinPaddingBuffers || c.numberOfPacketToFilter > 0 {
		buffers := c.unPadding(bufferBytes)

		if c.remainingContent == 0 && c.remainingPadding == 0 {
			if c.currentCommand == commandPaddingEnd {
				c.withinPaddingBuffers = false
				c.remainingContent = -1
				c.remainingPadding = -1
			} else if c.currentCommand == commandPaddingDirect {
				c.withinPaddingBuffers = false
				c.directRead = true

				inputBuffer, err := io.ReadAll(c.input)
				if err != nil {
					return 0, err
				}
				buffers = append(buffers, inputBuffer)

				rawInputBuffer, err := io.ReadAll(c.rawInput)
				if err != nil {
					return 0, err
				}

				buffers = append(buffers, rawInputBuffer)

				log.Debug("XtlsRead readV")
			} else if c.currentCommand == commandPaddingContinue {
				c.withinPaddingBuffers = true
			} else {
				return 0, fmt.Errorf("unknown command %v", c.currentCommand)
			}
		} else if c.remainingContent > 0 || c.remainingPadding > 0 {
			c.withinPaddingBuffers = true
		} else {
			c.withinPaddingBuffers = false
		}
		if c.numberOfPacketToFilter > 0 {
			c.filterTLS(buffers)
		}
		nBuffers := net.Buffers(buffers)
		c.remainingReader = &nBuffers
		return c.Read(p)
	} else {
		if c.numberOfPacketToFilter > 0 {
			c.filterTLS([][]byte{bufferBytes})
		}
		if chunkBuffer != nil {
			n = copy(p, bufferBytes)
		}
		return
	}
}

func (c *VisionConn) Write(p []byte) (n int, err error) {
	if c.numberOfPacketToFilter > 0 {
		c.filterTLS([][]byte{p})
	}
	if c.isPadding {
		inputLen := len(p)
		buffers := reshapeBuffer(p)
		var specIndex int
		for i, buffer := range buffers {
			if c.isTLS && len(buffer) > 6 && bytes.Equal(tlsApplicationDataStart, buffer[:3]) {
				var command byte = commandPaddingEnd
				if c.enableXTLS {
					c.directWrite = true
					specIndex = i
					command = commandPaddingDirect
				}
				c.isPadding = false
				buffers[i] = c.padding(buffer, command)
				break
			} else if !c.isTLS12orAbove && c.numberOfPacketToFilter <= 1 {
				c.isPadding = false
				buffers[i] = c.padding(buffer, commandPaddingEnd)
				break
			}
			buffers[i] = c.padding(buffer, commandPaddingContinue)
		}

		if c.directWrite {
			encryptedBuffer := buffers[:specIndex+1]

			for _, v := range encryptedBuffer {
				_, err = c.writer.Write(v)
				if err != nil {
					return
				}
			}
			buffers = buffers[specIndex+1:]
			c.writer = c.netConn
			time.Sleep(5 * time.Millisecond) // wtf
		}

		for _, v := range buffers {
			_, err = c.writer.Write(v)
			if err != nil {
				return
			}
		}
		n = inputLen
		return
	}

	if c.directWrite {
		return c.netConn.Write(p)
	} else {
		return c.Conn.Write(p)
	}
}

func (c *VisionConn) filterTLS(buffers [][]byte) {
	for _, buffer := range buffers {
		c.numberOfPacketToFilter--
		if len(buffer) > 6 {
			if buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 {
				c.isTLS = true
				if buffer[5] == 2 {
					c.isTLS12orAbove = true
					c.remainingServerHello = (int32(buffer[3])<<8 | int32(buffer[4])) + 5
					if len(buffer) >= 79 && c.remainingServerHello >= 79 {
						sessionIdLen := int32(buffer[43])
						cipherSuite := buffer[43+sessionIdLen+1 : 43+sessionIdLen+3]
						c.cipher = uint16(cipherSuite[0])<<8 | uint16(cipherSuite[1])
					} else {
						log.Info("XtlsFilterTls short server hello, tls 1.2 or older? ", len(buffer), " ", c.remainingServerHello)
					}
				}
			} else if bytes.Equal(tlsClientHandShakeStart, buffer[:2]) && buffer[5] == 1 {
				c.isTLS = true
				log.Debug("XtlsFilterTls found tls client hello! ", len(buffer))
			}
		}
		if c.remainingServerHello > 0 {
			end := int(c.remainingServerHello)
			if end > len(buffer) {
				end = len(buffer)
			}
			c.remainingServerHello -= int32(end)
			if bytes.Contains(buffer[:end], tls13SupportedVersions) {
				cipher, ok := tls13CipherSuiteDic[c.cipher]
				if ok && cipher != "TLS_AES_128_CCM_8_SHA256" {
					c.enableXTLS = true
				}
				log.Debug("XtlsFilterTls found tls 1.3! ", len(buffer), " ", c.cipher, " ", c.enableXTLS)
				c.numberOfPacketToFilter = 0
				return
			} else if c.remainingServerHello == 0 {
				log.Debug("XtlsFilterTls found tls 1.2! ", len(buffer))
				c.numberOfPacketToFilter = 0
				return
			}
		}
		if c.numberOfPacketToFilter == 0 {
			log.Debug("XtlsFilterTls stop filtering ", len(buffer))
		}
	}
}

func (c *VisionConn) padding(buffer []byte, command byte) []byte {
	contentLen := 0
	paddingLen := 0
	if buffer != nil {
		contentLen = len(buffer)
	}
	if contentLen < 900 && c.isTLS {
		l, _ := rand.Int(rand.Reader, big.NewInt(500))
		paddingLen = int(l.Int64()) + 900 - contentLen
	} else {
		l, _ := rand.Int(rand.Reader, big.NewInt(256))
		paddingLen = int(l.Int64())
	}
	var bufferLen int
	if c.writeUUID {
		bufferLen += 16
	}
	bufferLen += 5
	if buffer != nil {
		bufferLen += len(buffer)
	}
	bufferLen += paddingLen

	newBuffer := bytes.NewBuffer(nil)
	if c.writeUUID {
		newBuffer.Write(c.userUUID[:])
		c.writeUUID = false
	}
	newBuffer.Write([]byte{command, byte(contentLen >> 8), byte(contentLen), byte(paddingLen >> 8), byte(paddingLen)})
	if buffer != nil {
		newBuffer.Write(buffer)
	}
	newBuffer.Write(make([]byte, paddingLen))
	// newBuffer.Extend(paddingLen)
	log.Debug("XtlsPadding ", contentLen, " ", paddingLen, " ", command)
	return newBuffer.Bytes()
}

func (c *VisionConn) unPadding(buffer []byte) [][]byte {
	var bufferIndex int
	if c.remainingContent == -1 && c.remainingPadding == -1 {
		if len(buffer) >= 21 && bytes.Equal(c.userUUID[:], buffer[:16]) {
			bufferIndex = 16
			c.remainingContent = 0
			c.remainingPadding = 0
			c.currentCommand = 0
		}
	}
	if c.remainingContent == -1 && c.remainingPadding == -1 {
		return [][]byte{buffer}
	}
	var buffers [][]byte
	for bufferIndex < len(buffer) {
		if c.remainingContent <= 0 && c.remainingPadding <= 0 {
			if c.currentCommand == 1 {
				buffers = append(buffers, buffer[bufferIndex:])
				break
			} else {
				paddingInfo := buffer[bufferIndex : bufferIndex+5]
				c.currentCommand = paddingInfo[0]
				c.remainingContent = int(paddingInfo[1])<<8 | int(paddingInfo[2])
				c.remainingPadding = int(paddingInfo[3])<<8 | int(paddingInfo[4])
				bufferIndex += 5
				log.Debug("Xtls Unpadding new block ", bufferIndex, " ", c.remainingContent, " padding ", c.remainingPadding, " ", c.currentCommand)
			}
		} else if c.remainingContent > 0 {
			end := c.remainingContent
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			buffers = append(buffers, buffer[bufferIndex:bufferIndex+end])
			c.remainingContent -= end
			bufferIndex += end
		} else {
			end := c.remainingPadding
			if end > len(buffer)-bufferIndex {
				end = len(buffer) - bufferIndex
			}
			c.remainingPadding -= end
			bufferIndex += end
		}
		if bufferIndex == len(buffer) {
			break
		}
	}
	return buffers
}

func (c *VisionConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *VisionConn) Upstream() any {
	return c.Conn
}
