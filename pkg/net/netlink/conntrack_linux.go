//go:build !android

package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// conntrackResolver recovers the original tuple of a NATed flow. A flow
// forwarded from a container is usually masqueraded before it reaches a TUN
// device, so the observed source is the node address and port; conntrack
// still records the container's own address and port. Each query is a single
// CT_GET keyed by the reply tuple, never a table dump.
type conntrackResolver struct {
	mu  sync.Mutex
	fd  int
	seq uint32
	buf []byte
}

const (
	nfnlSubsysCTNetlink = 1
	ipctnlMsgCTNew      = 0
	ipctnlMsgCTGet      = 1

	ctaTupleOrig  = 1
	ctaTupleReply = 2
	ctaTupleIP    = 1
	ctaTupleProto = 2
	ctaIPv4Src    = 1
	ctaIPv4Dst    = 2
	ctaIPv6Src    = 3
	ctaIPv6Dst    = 4
	ctaProtoNum   = 1
	ctaProtoSrc   = 2
	ctaProtoDst   = 3

	nlaFNested    = 0x8000
	nlaTypeMask   = ^uint16(0xc000)
	nfGenMsgLen   = 4
	conntrackRecv = 8 << 10
)

// errConntrackUnavailable marks a kernel or permission failure, after which
// the resolver is no longer consulted.
var errConntrackUnavailable = errors.New("conntrack unavailable")

func newConntrackResolver() (*conntrackResolver, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errConntrackUnavailable, err)
	}
	if err := setNetlinkTimeouts(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &conntrackResolver{fd: fd, buf: make([]byte, conntrackRecv)}, nil
}

func setNetlinkTimeouts(fd int) error {
	timeout := unix.NsecToTimeval(netNSDiagTimeout.Nanoseconds())
	return errors.Join(unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout),
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &timeout))
}

// original returns the original-direction tuple of the tracked flow whose
// reply direction is dst -> src, which is what a flow observed as src -> dst
// expects in reply. ok is false when conntrack does not track the flow.
func (c *conntrackResolver) original(protocol uint8, src, dst netip.AddrPort) (osrc, odst netip.AddrPort, ok bool, err error) {
	req, err := encodeConntrackGet(protocol, dst, src)
	if err != nil {
		return osrc, odst, false, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return osrc, odst, false, errConntrackUnavailable
	}
	c.seq++
	binary.NativeEndian.PutUint32(req[8:12], c.seq)
	if err := unix.Sendto(c.fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return osrc, odst, false, fmt.Errorf("conntrack request: %w", err)
	}
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return osrc, odst, false, fmt.Errorf("conntrack response: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(c.buf[:n])
		if err != nil {
			return osrc, odst, false, err
		}
		for _, m := range msgs {
			if m.Header.Seq != c.seq {
				continue // a late reply to an earlier, timed-out request
			}
			switch m.Header.Type {
			case unix.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return osrc, odst, false, errors.New("conntrack: short error")
				}
				switch errno := unix.Errno(-int32(binary.NativeEndian.Uint32(m.Data[:4]))); errno {
				case 0, unix.ENOENT:
					return osrc, odst, false, nil
				case unix.EPERM, unix.EOPNOTSUPP, unix.EPROTONOSUPPORT, unix.EAFNOSUPPORT:
					return osrc, odst, false, fmt.Errorf("%w: %w", errConntrackUnavailable, errno)
				default:
					return osrc, odst, false, fmt.Errorf("conntrack: %w", errno)
				}
			case nfnlSubsysCTNetlink<<8 | ipctnlMsgCTNew:
				osrc, odst, ok = parseConntrackOriginal(m.Data)
				if !ok {
					return osrc, odst, false, errors.New("conntrack: malformed reply")
				}
				return osrc, odst, true, nil
			}
		}
	}
}

func (c *conntrackResolver) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

// encodeConntrackGet builds a CT_GET request for the flow whose reply
// direction is src -> dst. The sequence number is filled in by the caller.
func encodeConntrackGet(protocol uint8, src, dst netip.AddrPort) ([]byte, error) {
	sa, da := src.Addr().Unmap(), dst.Addr().Unmap()
	if sa.Is4() != da.Is4() {
		return nil, errors.New("conntrack: mixed address families")
	}
	family, srcType, dstType := uint8(unix.AF_INET6), uint16(ctaIPv6Src), uint16(ctaIPv6Dst)
	if sa.Is4() {
		family, srcType, dstType = unix.AF_INET, ctaIPv4Src, ctaIPv4Dst
	}
	b := make([]byte, unix.NLMSG_HDRLEN, 128)
	binary.NativeEndian.PutUint16(b[4:6], nfnlSubsysCTNetlink<<8|ipctnlMsgCTGet)
	binary.NativeEndian.PutUint16(b[6:8], unix.NLM_F_REQUEST)
	b = append(b, family, 0, 0, 0) // nfgenmsg: family, NFNETLINK_V0, res_id
	tuple := len(b)
	b = appendAttrHeader(b, ctaTupleReply|nlaFNested)
	ip := len(b)
	b = appendAttrHeader(b, ctaTupleIP|nlaFNested)
	b = appendAttr(b, srcType, sa.AsSlice())
	b = appendAttr(b, dstType, da.AsSlice())
	closeAttr(b, ip)
	proto := len(b)
	b = appendAttrHeader(b, ctaTupleProto|nlaFNested)
	b = appendAttr(b, ctaProtoNum, []byte{protocol})
	b = appendAttr(b, ctaProtoSrc, binary.BigEndian.AppendUint16(nil, src.Port()))
	b = appendAttr(b, ctaProtoDst, binary.BigEndian.AppendUint16(nil, dst.Port()))
	closeAttr(b, proto)
	closeAttr(b, tuple)
	binary.NativeEndian.PutUint32(b[0:4], uint32(len(b)))
	return b, nil
}

func appendAttrHeader(b []byte, typ uint16) []byte {
	return binary.NativeEndian.AppendUint16(binary.NativeEndian.AppendUint16(b, 0), typ)
}

func appendAttr(b []byte, typ uint16, value []byte) []byte {
	b = binary.NativeEndian.AppendUint16(b, uint16(unix.SizeofRtAttr+len(value)))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, value...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// closeAttr sets the length of the nested attribute started at offset.
func closeAttr(b []byte, offset int) {
	binary.NativeEndian.PutUint16(b[offset:offset+2], uint16(len(b)-offset))
}

// walkAttrs visits each netlink attribute in b with the nested flag cleared.
func walkAttrs(b []byte, visit func(typ uint16, value []byte)) bool {
	for len(b) >= unix.SizeofRtAttr {
		size := int(binary.NativeEndian.Uint16(b[0:2]))
		if size < unix.SizeofRtAttr || size > len(b) {
			return false
		}
		visit(binary.NativeEndian.Uint16(b[2:4])&nlaTypeMask, b[unix.SizeofRtAttr:size])
		size = (size + 3) &^ 3
		if size > len(b) {
			return true
		}
		b = b[size:]
	}
	return true
}

func parseConntrackOriginal(data []byte) (src, dst netip.AddrPort, ok bool) {
	if len(data) < nfGenMsgLen {
		return src, dst, false
	}
	found := false
	walkAttrs(data[nfGenMsgLen:], func(typ uint16, value []byte) {
		if typ == ctaTupleOrig && !found {
			src, dst, found = parseConntrackTuple(value)
		}
	})
	return src, dst, found
}

func parseConntrackTuple(b []byte) (src, dst netip.AddrPort, ok bool) {
	var sa, da netip.Addr
	var sp, dp uint16
	var havePorts int
	walkAttrs(b, func(typ uint16, value []byte) {
		switch typ {
		case ctaTupleIP:
			walkAttrs(value, func(typ uint16, value []byte) {
				switch {
				case (typ == ctaIPv4Src || typ == ctaIPv6Src) && (len(value) == 4 || len(value) == 16):
					sa, _ = netip.AddrFromSlice(value)
				case (typ == ctaIPv4Dst || typ == ctaIPv6Dst) && (len(value) == 4 || len(value) == 16):
					da, _ = netip.AddrFromSlice(value)
				}
			})
		case ctaTupleProto:
			walkAttrs(value, func(typ uint16, value []byte) {
				if len(value) < 2 {
					return
				}
				switch typ {
				case ctaProtoSrc:
					sp, havePorts = binary.BigEndian.Uint16(value), havePorts|1
				case ctaProtoDst:
					dp, havePorts = binary.BigEndian.Uint16(value), havePorts|2
				}
			})
		}
	})
	if !sa.IsValid() || !da.IsValid() || havePorts != 3 {
		return src, dst, false
	}
	return netip.AddrPortFrom(sa.Unmap(), sp), netip.AddrPortFrom(da.Unmap(), dp), true
}
