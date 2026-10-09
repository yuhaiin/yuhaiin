package fixed

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestServerCloseBeforeLazyListen(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			srv, err := NewServer(ServerConfig{Host: "127.0.0.1:0"})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { srv.Close() })
			if err := srv.Close(); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if network == "tcp" {
					conn, acceptErr := srv.Accept()
					err = acceptErr
					if conn != nil {
						conn.Close()
					}
				} else {
					conn, packetErr := srv.Packet(t.Context())
					err = packetErr
					if conn != nil {
						conn.Close()
					}
				}
				result <- err
			}()
			select {
			case err := <-result:
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("listen after Close = %v, want net.ErrClosed", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Accept created a listener after Close")
			}
		})
	}
}
