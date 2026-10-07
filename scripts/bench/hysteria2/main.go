// Command hysteria2-bench is a process-isolated interoperability and throughput
// fixture. It exercises the native inbound handler/NAT and client adapters.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	ci "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	cn "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/hysteria2"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

var (
	mode           = flag.String("mode", "client", "target, server, or client")
	listen         = flag.String("listen", "127.0.0.1:4433", "target/server listen address")
	serverAddr     = flag.String("server", "127.0.0.1:4433", "Hysteria server or official forwarding address")
	target         = flag.String("target", "127.0.0.1:9000", "proxy target")
	implementation = flag.String("implementation", "native", "native or direct (official client uses a local forward)")
	caFile         = flag.String("ca", "", "client CA PEM file")
	certFile       = flag.String("cert", "", "server leaf certificate PEM")
	keyFile        = flag.String("key", "", "server key PEM")
	autoDir        = flag.String("auto-dir", "", "persist TLS-auto state and export public CA in this directory")
	auth           = flag.String("auth", "benchmark-secret", "Hysteria auth")
	salamander     = flag.String("salamander", "", "optional obfuscation password")
	bandwidth      = flag.Uint64("bandwidth-bps", 0, "up/down bandwidth in bytes per second; zero uses BBR")
	relayBuffer    = flag.Int("relay-buffer-size", 16384, "native server relay buffer, matching the advanced setting")
	direction      = flag.String("direction", "upload", "upload or download")
	count          = flag.Int64("bytes", 64<<20, "payload bytes per TCP stream")
	streams        = flag.Int("streams", 1, "concurrent TCP streams")
	udpPackets     = flag.Int("udp-packets", 0, "nonzero selects a UDP echo/loss test")
	udpSize        = flag.Int("udp-size", 1000, "UDP payload size including sequence number")
	udpPPS         = flag.Int("udp-pps", 10000, "paced offered UDP packets per second")
)

func output(v any) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		panic(err)
	}
}
func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch *mode {
	case "target":
		return runTarget(ctx)
	case "server":
		return runServer(ctx)
	case "client":
		return runClient(ctx)
	default:
		return fmt.Errorf("unknown mode %q", *mode)
	}
}

func runServer(ctx context.Context) error {
	if *relayBuffer <= 2048 || *relayBuffer >= 65535 {
		return fmt.Errorf("invalid relay buffer size")
	}
	configuration.RelayBufferSize.Store(*relayBuffer)
	runtime := inbound.NewInbound(direct.Default)
	defer runtime.Close()
	config := ci.Inbound{ID: "hysteria2-bench", Name: "hysteria2-bench", Enabled: true, Network: ci.NewTypedNetwork(ci.TCPUDPNetwork{Host: *listen, UDP: ci.UDPUdpOnly}), Protocol: ci.NewTypedProtocol(ci.Hysteria2Protocol{Auth: *auth, SalamanderPassword: *salamander, UploadBPS: *bandwidth, DownloadBPS: *bandwidth})}
	if *autoDir != "" {
		if err := os.MkdirAll(*autoDir, 0700); err != nil {
			return err
		}
		db, err := sqlite.Open(ctx, filepath.Join(*autoDir, "state.db"))
		if err != nil {
			return err
		}
		defer db.Close()
		storage := store.NewInboundStore(db.DB())
		if previous, err := storage.Get(ctx, config.ID); err == nil {
			config.Transports = previous.Transports
		} else {
			config.Transports = []ci.Transport{ci.NewTypedTransport(ci.TLSAutoTransport{ServerNames: []string{"bench.example"}})}
		}
		controller := inbound.NewContractStore(storage, runtime)
		if err := controller.Save(ctx, config, 0); err != nil {
			return err
		}
		saved, err := storage.Get(ctx, config.ID)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*autoDir, "ca.pem"), saved.Transports[0].TLSAuto.CACertBase64, 0600); err != nil {
			return err
		}
	} else {
		config.Transports = []ci.Transport{ci.NewTypedTransport(ci.TLSTransport{TLS: &ci.ServerTLSConfig{Certificates: []ci.Certificate{{CertFile: *certFile, KeyFile: *keyFile}}}})}
		if err := runtime.SaveContract(config); err != nil {
			return err
		}
	}
	output(map[string]any{"ready": *listen})
	<-ctx.Done()
	return nil
}

func runTarget(ctx context.Context) error {
	tcp, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		return err
	}
	defer udp.Close()
	go func() { <-ctx.Done(); _ = tcp.Close(); _ = udp.Close() }()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], addr)
		}
	}()
	output(map[string]any{"ready": tcp.Addr().String()})
	for {
		conn, err := tcp.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
			header := make([]byte, 9)
			if _, err := io.ReadFull(conn, header); err != nil {
				return
			}
			n := int64(binary.BigEndian.Uint64(header[1:]))
			if n <= 0 || n > 8<<30 {
				return
			}
			if header[0] == 'U' {
				received := n
				if err := verifyPayload(conn, n); err != nil {
					return
				}
				binary.BigEndian.PutUint64(header[:8], uint64(received))
				_, _ = conn.Write(header[:8])
			} else {
				_ = writePayload(conn, n)
			}
		}()
	}
}

func writePayload(w io.Writer, n int64) error {
	data := bytes.Repeat([]byte{0x5a}, 64<<10)
	for n > 0 {
		chunk := min(int64(len(data)), n)
		written, err := w.Write(data[:chunk])
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		n -= int64(written)
	}
	return nil
}

func verifyPayload(r io.Reader, n int64) error {
	buf := make([]byte, 64<<10)
	expected := bytes.Repeat([]byte{0x5a}, len(buf))
	for n > 0 {
		chunk := min(int64(len(buf)), n)
		read, err := io.ReadFull(r, buf[:chunk])
		if err != nil {
			return err
		}
		if !bytes.Equal(buf[:read], expected[:read]) {
			return fmt.Errorf("payload corruption")
		}
		n -= int64(read)
	}
	return nil
}

func runClient(ctx context.Context) error {
	if *count <= 0 || *streams <= 0 || *udpSize < 8 || *udpSize > 65507 || *udpPPS <= 0 {
		return fmt.Errorf("invalid workload")
	}
	proxy := direct.Default
	if *implementation == "native" {
		var roots [][]byte
		if *caFile != "" {
			ca, err := os.ReadFile(*caFile)
			if err != nil {
				return err
			}
			roots = [][]byte{ca}
		}
		var err error
		proxy, err = hysteria2.NewClient(cn.Hysteria2{Host: *serverAddr, Auth: *auth, SalamanderPassword: *salamander, UploadBPS: *bandwidth, DownloadBPS: *bandwidth, TLS: cn.TLS{ServerNames: []string{"bench.example"}, CACert: roots}}, nil)
		if err != nil {
			return err
		}
		defer proxy.Close()
	} else if *implementation != "direct" {
		return fmt.Errorf("unknown client implementation")
	}
	network := "tcp"
	if *udpPackets > 0 {
		network = "udp"
	}
	address, err := netapi.ParseAddress(network, *target)
	if err != nil {
		return err
	}
	if *udpPackets > 0 {
		return runUDP(ctx, proxy, address)
	}
	conns := make([]net.Conn, *streams)
	for i := range conns {
		conn, err := proxy.Conn(ctx, address)
		if err != nil {
			return err
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
		conns[i] = conn
	}
	start := time.Now()
	results := make(chan error, len(conns))
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Go(func() {
			header := make([]byte, 9)
			header[0] = 'U'
			if *direction == "download" {
				header[0] = 'D'
			}
			binary.BigEndian.PutUint64(header[1:], uint64(*count))
			if _, err := conn.Write(header); err != nil {
				results <- err
				return
			}
			if header[0] == 'U' {
				if err := writePayload(conn, *count); err != nil {
					results <- err
					return
				}
				if _, err := io.ReadFull(conn, header[:8]); err != nil {
					results <- err
					return
				}
				if binary.BigEndian.Uint64(header[:8]) != uint64(*count) {
					results <- fmt.Errorf("server received wrong byte count")
					return
				}
			} else {
				if err := verifyPayload(conn, *count); err != nil {
					results <- err
					return
				}
			}
			results <- nil
		})
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	for range conns {
		if err := <-results; err != nil {
			return err
		}
	}
	total := *count * int64(len(conns))
	output(map[string]any{"transport": "tcp", "direction": *direction, "streams": len(conns), "payload_bytes": total, "seconds": elapsed, "mbps": float64(total) * 8 / elapsed / 1e6})
	return nil
}

func runUDP(ctx context.Context, proxy netapi.Proxy, address netapi.Address) error {
	packet, err := proxy.PacketConn(ctx, address)
	if err != nil {
		return err
	}
	defer packet.Close()
	_ = packet.SetReadDeadline(time.Now().Add(120 * time.Second))
	done := make(chan struct{})
	seen := make([]bool, *udpPackets)
	received, corrupt := 0, 0
	var last time.Time
	start := time.Now()
	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		for {
			n, _, err := packet.ReadFrom(buf)
			if err != nil {
				return
			}
			if n != *udpSize {
				corrupt++
				continue
			}
			id := binary.BigEndian.Uint64(buf[:8])
			if id >= uint64(len(seen)) {
				corrupt++
				continue
			}
			for _, b := range buf[8:n] {
				if b != 0x5a {
					corrupt++
					break
				}
			}
			if !seen[id] {
				seen[id] = true
				received++
				last = time.Now()
			}
		}
	}()
	data := bytes.Repeat([]byte{0x5a}, *udpSize)
	interval := time.Second / time.Duration(*udpPPS)
	for i := range *udpPackets {
		binary.BigEndian.PutUint64(data, uint64(i))
		if _, err := packet.WriteTo(data, address); err != nil {
			_ = packet.Close()
			<-done
			return err
		}
		next := start.Add(time.Duration(i+1) * interval)
		if delay := time.Until(next); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				_ = packet.Close()
				<-done
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	sendSeconds := time.Since(start).Seconds()
	_ = packet.SetReadDeadline(time.Now().Add(time.Second))
	<-done
	seconds := last.Sub(start).Seconds()
	if seconds <= 0 {
		seconds = sendSeconds
	}
	output(map[string]any{"transport": "udp", "sent": *udpPackets, "received": received, "loss_percent": 100 * float64(*udpPackets-received) / float64(*udpPackets), "corrupt": corrupt, "payload_size": *udpSize, "send_seconds": sendSeconds, "seconds": seconds, "offered_mbps": float64(*udpPackets**udpSize) * 8 / sendSeconds / 1e6, "mbps": float64(received**udpSize) * 8 / seconds / 1e6})
	if corrupt > 0 || received == 0 {
		return fmt.Errorf("UDP integrity/forwarding failure")
	}
	return nil
}
