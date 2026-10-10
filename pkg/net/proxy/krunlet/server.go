// Package krunlet implements the native Unix stream inbound for Krunlet
// microVM traffic. The virtio-net/gVisor TCP/IP endpoint runs in Krunlet;
// this package hands flows directly to yuhaiin's existing routing pipeline.
package krunlet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

const (
	protocolTCP = 1
	protocolUDP = 2
	maxPacket   = 65535
)

// Server owns the Unix listener and active TCP/UDP flows. Socket paths
// are host-local and do not require any exposed TCP listen ports.
type Server struct {
	netapi.EmptyInterface
	listener net.Listener
	path     string
	handler  netapi.Handler
	mu       sync.Mutex
	peers    map[net.Conn]struct{}
	closed   bool
	wg       sync.WaitGroup
}

func NewServer(path string, handler netapi.Handler) (*Server, error) {
	if !filepath.IsAbs(path) || path == "" {
		return nil, errors.New("krunlet inbound socket must be an absolute path")
	}
	if info, err := os.Lstat(path); err == nil {
		return nil, fmt.Errorf("krunlet inbound socket already exists (%s, mode %s)", path, info.Mode())
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	s := &Server{listener: listener, path: path, handler: handler, peers: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go s.serve()
	return s, nil
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.peers[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.peers, conn)
				s.mu.Unlock()
				_ = conn.Close()
			}()
			_ = s.handle(conn)
		}()
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	_ = s.listener.Close()
	for conn := range s.peers {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	// net.UnixListener unlinks its path on Close by default. Avoid an
	// erroneous ENOENT on normal shutdown while still reporting unexpected
	// filesystem cleanup failures.
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type request struct {
	protocol byte
	src      netip.AddrPort
	dst      netip.AddrPort
}

func readRequest(r io.Reader) (request, error) {
	var hdr [10]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return request{}, err
	}
	if string(hdr[:4]) != "KRN1" {
		return request{}, errors.New("unsupported krunlet inbound wire version")
	}
	if hdr[4] != protocolTCP && hdr[4] != protocolUDP {
		return request{}, errors.New("unsupported network transport")
	}
	var ipLen int
	switch hdr[5] {
	case 4:
		ipLen = 4
	case 6:
		ipLen = 16
	default:
		return request{}, errors.New("invalid IP address family")
	}
	var ips [32]byte
	if _, err := io.ReadFull(r, ips[:ipLen*2]); err != nil {
		return request{}, err
	}
	src, ok := netip.AddrFromSlice(ips[:ipLen])
	if !ok {
		return request{}, errors.New("invalid source IP")
	}
	dst, ok := netip.AddrFromSlice(ips[ipLen : ipLen*2])
	if !ok || dst.IsUnspecified() {
		return request{}, errors.New("invalid destination IP")
	}
	srcPort := binary.BigEndian.Uint16(hdr[6:8])
	dstPort := binary.BigEndian.Uint16(hdr[8:10])
	if dstPort == 0 {
		return request{}, errors.New("destination port must not be zero")
	}
	return request{protocol: hdr[4], src: netip.AddrPortFrom(src, srcPort), dst: netip.AddrPortFrom(dst, dstPort)}, nil
}

func (s *Server) handle(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	req, err := readRequest(conn)
	if err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Time{})
	var netproto string
	var srcAddr net.Addr
	var dstAddr net.Addr
	if req.protocol == protocolTCP {
		netproto = "tcp"
		srcAddr = net.TCPAddrFromAddrPort(req.src)
		dstAddr = net.TCPAddrFromAddrPort(req.dst)
	} else {
		netproto = "udp"
		srcAddr = net.UDPAddrFromAddrPort(req.src)
		dstAddr = net.UDPAddrFromAddrPort(req.dst)
	}
	dst := netapi.ParseIPAddr(netproto, req.dst.Addr().AsSlice(), req.dst.Port())
	if req.protocol == protocolTCP {
		s.handler.HandleStream(&netapi.StreamMeta{
			Source: srcAddr, Destination: dstAddr,
			Src: conn, Address: dst,
		})
		return nil
	}
	var writeMu sync.Mutex
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint16(hdr[:]))
		if size == 0 {
			return errors.New("empty UDP datagram")
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(conn, body); err != nil {
			return err
		}
		writeBack := netapi.WriteBackFunc(func(payload []byte, _ net.Addr) (int, error) {
			if len(payload) == 0 || len(payload) > maxPacket {
				return 0, errors.New("invalid UDP response length")
			}
			var frame [2]byte
			binary.BigEndian.PutUint16(frame[:], uint16(len(payload)))
			writeMu.Lock()
			defer writeMu.Unlock()
			if err := writeAll(conn, frame[:]); err != nil {
				return 0, err
			}
			if err := writeAll(conn, payload); err != nil {
				return 0, err
			}
			return len(payload), nil
		})
		s.handler.HandlePacket(netapi.NewPacket(srcAddr, dst, body, writeBack))
	}
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
