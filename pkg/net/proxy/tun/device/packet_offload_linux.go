package device

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// offloadTUN retains kernel-generated TCP super-packets instead of splitting
// them into MTU-sized scratch buffers. Only the lightweight packet adapter uses
// this device; legacy WireGuard/gVisor devices keep their existing contract.
type offloadTUN struct {
	file        *os.File
	mtu, prefix int
	tso         bool
	readMu      sync.Mutex
	readBuffer  []byte
	closed      bool
	once        sync.Once
	closeErr    error
}

func newOffloadTUN(fd, mtu int, name string) (*offloadTUN, error) {
	prefix, err := unix.IoctlGetInt(fd, unix.TUNGETVNETHDRSZ)
	if err != nil {
		return nil, fmt.Errorf("get TUN virtio header size: %w", err)
	}
	if prefix < tunVnetHdrLen || prefix > 64 {
		return nil, fmt.Errorf("invalid TUN virtio header size %d", prefix)
	}
	// Use explicit little endian rather than depending on legacy host byte order.
	if err := unix.IoctlSetPointerInt(fd, unix.TUNSETVNETLE, 1); err != nil {
		return nil, fmt.Errorf("set TUN virtio byte order: %w", err)
	}
	const tcpOffloads = unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6
	tso := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, tcpOffloads) == nil
	if !tso {
		if err := unix.IoctlSetInt(fd, unix.TUNSETOFFLOAD, unix.TUN_F_CSUM); err != nil {
			return nil, fmt.Errorf("negotiate TUN checksum offload: %w", err)
		}
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	return &offloadTUN{file: os.NewFile(uintptr(fd), name), mtu: mtu, prefix: prefix, tso: tso}, nil
}

func (d *offloadTUN) BatchSize() int   { return 1 }
func (d *offloadTUN) Offset() int      { return d.prefix }
func (d *offloadTUN) MTU() int         { return d.mtu }
func (d *offloadTUN) GSOEnabled() bool { return d.tso }
func (d *offloadTUN) MaxGSOPacketSize() int {
	if d.tso {
		return 65535
	}
	return 0
}
func (d *offloadTUN) Close() error {
	d.once.Do(func() {
		d.closeErr = d.file.Close()
		d.readMu.Lock()
		d.closed = true
		d.readBuffer = nil
		d.readMu.Unlock()
	})
	return d.closeErr
}
func (d *offloadTUN) ReadPacketView() ([]byte, bool, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	return d.readPacketView()
}
func (d *offloadTUN) readPacketView() ([]byte, bool, error) {
	if d.closed {
		return nil, false, os.ErrClosed
	}
	if d.readBuffer == nil {
		d.readBuffer = make([]byte, 65575+d.prefix)
	}
	n, err := d.file.Read(d.readBuffer)
	if n == 0 {
		return nil, false, err
	}
	packet, verified, decodeErr := decodeVirtioPacket(d.readBuffer[:n], d.prefix)
	if decodeErr != nil {
		return nil, false, decodeErr
	}
	return packet, verified, err
}
func (d *offloadTUN) Read(bufs [][]byte, sizes []int) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	packet, verified, err := d.readPacketView()
	if len(packet) == 0 {
		return 0, err
	}
	if len(bufs) == 0 || len(sizes) == 0 || len(bufs[0]) < d.prefix+len(packet) {
		return 0, io.ErrShortBuffer
	}
	sizes[0] = copy(bufs[0][d.prefix:], packet)
	if verified {
		// Complete a partial checksum for callers that do not carry the trust
		// metadata. The packet-view fast path does not scan payload bytes.
		flags := d.readBuffer[0]
		if flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
			start := int(binary.LittleEndian.Uint16(d.readBuffer[6:8]))
			at := start + int(binary.LittleEndian.Uint16(d.readBuffer[8:10]))
			p := bufs[0][d.prefix : d.prefix+sizes[0]]
			value := ^packetSum(p[start:])
			if value == 0 && at-start == 6 {
				value = 0xffff // UDP transmits a computed zero as all ones.
			}
			binary.BigEndian.PutUint16(p[at:], value)
		}
	}
	return 1, err
}
func (d *offloadTUN) Write(bufs [][]byte) (int, error) {
	for i, b := range bufs {
		if err := d.WritePacketBuffer(b, d.prefix, 0); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}
func (d *offloadTUN) WritePacketBuffer(b []byte, offset, segmentSize int) error {
	if offset < d.prefix || offset > len(b) {
		return io.ErrShortBuffer
	}
	header := b[offset-d.prefix : offset]
	packet := b[offset:]
	clear(header)
	if segmentSize != 0 {
		if !d.tso {
			return fmt.Errorf("TCP segmentation is unavailable")
		}
		if err := encodeVirtioTCP(header, packet, segmentSize, d.mtu); err != nil {
			return err
		}
	} else if len(packet) > d.mtu {
		return fmt.Errorf("plain packet exceeds TUN MTU")
	}
	n, err := d.file.Write(b[offset-d.prefix:])
	if err == nil && n != d.prefix+len(packet) {
		return io.ErrShortWrite
	}
	return err
}

func badVirtioPacket(reason string) error {
	// The bad record has been consumed. The stack counts/drops it and keeps
	// reading, just as with an oversized record; it must not tear down the TUN.
	return fmt.Errorf("invalid TUN virtio packet (%s): %w", reason, io.ErrShortBuffer)
}

func decodeVirtioPacket(b []byte, prefix int) ([]byte, bool, error) {
	if prefix < tunVnetHdrLen || prefix > len(b) || len(b)-prefix == 0 {
		return nil, false, badVirtioPacket("header length")
	}
	packet := b[prefix:]
	flags, kind := b[0], b[1]
	if flags & ^uint8(unix.VIRTIO_NET_HDR_F_NEEDS_CSUM|unix.VIRTIO_NET_HDR_F_DATA_VALID) != 0 {
		return nil, false, badVirtioPacket("flags")
	}
	if kind == unix.VIRTIO_NET_HDR_GSO_NONE && flags == 0 {
		return packet, false, nil
	}
	version, ih, proto, th, err := packetTransport(packet)
	if err != nil {
		return nil, false, err
	}
	if flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
		offset := 16
		if proto == unix.IPPROTO_UDP {
			offset = 6
		}
		if int(binary.LittleEndian.Uint16(b[6:8])) != ih || int(binary.LittleEndian.Uint16(b[8:10])) != offset {
			return nil, false, badVirtioPacket("checksum offsets")
		}
	}
	if kind != unix.VIRTIO_NET_HDR_GSO_NONE {
		baseKind := kind & ^uint8(unix.VIRTIO_NET_HDR_GSO_ECN)
		if proto != unix.IPPROTO_TCP || flags&unix.VIRTIO_NET_HDR_F_NEEDS_CSUM == 0 || version == 4 && baseKind != unix.VIRTIO_NET_HDR_GSO_TCPV4 || version == 6 && baseKind != unix.VIRTIO_NET_HDR_GSO_TCPV6 {
			return nil, false, badVirtioPacket("GSO type")
		}
		h := int(binary.LittleEndian.Uint16(b[2:4]))
		if h < ih+th || h > len(packet) || binary.LittleEndian.Uint16(b[4:6]) == 0 {
			return nil, false, badVirtioPacket("GSO lengths")
		}
	}
	return packet, flags != 0, nil
}

// Validate transport offsets without interpreting incomplete checksums. Ordinary
// IP options/extensions and checksum validation still belong to the core parser.
func packetTransport(p []byte) (version, ih, proto, th int, err error) {
	bad := func() (int, int, int, int, error) { return 0, 0, 0, 0, badVirtioPacket("IP/transport structure") }
	if len(p) < 20 {
		return bad()
	}
	version = int(p[0] >> 4)
	switch version {
	case 4:
		ih, proto = int(p[0]&15)*4, int(p[9])
		if ih < 20 || ih > len(p) || int(binary.BigEndian.Uint16(p[2:4])) != len(p) || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return bad()
		}
	case 6:
		if len(p) < 40 || 40+int(binary.BigEndian.Uint16(p[4:6])) != len(p) {
			return bad()
		}
		ih, proto = 40, int(p[6])
		for count := 0; proto == 0 || proto == 43 || proto == 60; count++ {
			if count >= 8 || ih+2 > len(p) {
				return bad()
			}
			n := (int(p[ih+1]) + 1) * 8
			if n > len(p)-ih {
				return bad()
			}
			proto, ih = int(p[ih]), ih+n
		}
	default:
		return bad()
	}
	switch proto {
	case unix.IPPROTO_TCP:
		if len(p)-ih < 20 {
			return bad()
		}
		th = int(p[ih+12]>>4) * 4
		if th < 20 || th > len(p)-ih {
			return bad()
		}
	case unix.IPPROTO_UDP:
		th = 8
		if len(p)-ih < th || int(binary.BigEndian.Uint16(p[ih+4:ih+6])) != len(p)-ih {
			return bad()
		}
	default:
		return bad()
	}
	return version, ih, proto, th, nil
}

func encodeVirtioTCP(header, p []byte, segmentSize, mtu int) error {
	version, ih, proto, th, err := packetTransport(p)
	if err != nil {
		return err
	}
	if len(header) < tunVnetHdrLen || len(p) > 65535 || proto != unix.IPPROTO_TCP || segmentSize <= 0 || segmentSize > mtu-ih-th || p[ih+13] & ^byte(0x18) != 0 {
		return badVirtioPacket("TCP output limits")
	}
	header[0] = unix.VIRTIO_NET_HDR_F_NEEDS_CSUM
	header[1] = unix.VIRTIO_NET_HDR_GSO_TCPV4
	if version == 6 {
		header[1] = unix.VIRTIO_NET_HDR_GSO_TCPV6
	}
	binary.LittleEndian.PutUint16(header[2:4], uint16(ih+th))
	binary.LittleEndian.PutUint16(header[4:6], uint16(segmentSize))
	binary.LittleEndian.PutUint16(header[6:8], uint16(ih))
	binary.LittleEndian.PutUint16(header[8:10], 16)
	return nil
}

func packetSum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) == 1 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return uint16(sum)
}
