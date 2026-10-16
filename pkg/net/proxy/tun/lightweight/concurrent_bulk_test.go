package lightweight

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestConcurrentBulk(t *testing.T) {
	a, z := stackPairConfig(t, Config{MTU: 1280, QueuePackets: 2})
	l, err := z.ListenTCP(netip.MustParseAddrPort("192.0.2.2:8080"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var clients, servers []net.Conn
	for range 100 {
		c, err := a.DialContextTCP(t.Context(), netip.MustParseAddrPort("192.0.2.2:8080"))
		if err != nil {
			t.Fatal(err)
		}
		p, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		servers = append(servers, p)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	data := bytes.Repeat([]byte{0xa5}, 65536)
	for i, c := range clients {
		server := servers[i]
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_ = server.SetDeadline(time.Now().Add(5 * time.Second))
		wg.Go(func() {
			marker := make([]byte, 1)
			_, err := io.ReadFull(server, marker)
			if err == nil {
				_, err = server.Write(data)
			}
			errs <- err
		})
		wg.Go(func() {
			buf := make([]byte, len(data))
			_, err := c.Write([]byte{1})
			n := 0
			if err == nil {
				n, err = io.ReadFull(c, buf)
			}
			if err != nil || !bytes.Equal(data, buf) {
				errs <- fmt.Errorf("flow %d read %d: %w", i, n, err)
				return
			}
			errs <- nil
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err, a.Stats(), z.Stats())
		}
	}
	for i, c := range clients {
		_ = c.Close()
		_ = servers[i].Close()
	}
}
