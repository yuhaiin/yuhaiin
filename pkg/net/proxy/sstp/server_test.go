package sstp

import (
    "bytes"
    "net/netip"
    "strings"
    "testing"
)

func TestServerHTTPHandshake(t *testing.T) {
    request := "SSTP_DUPLEX_POST " + sstpURI + " HTTP/1.1\r\nHost: vpn.example.com\r\nContent-Length: 18446744073709551615\r\n\r\n"
    buf := bytes.NewBufferString(request)
    if err := acceptSSTPHTTP(buf); err != nil { t.Fatal(err) }
    if !strings.HasPrefix(buf.String(), "HTTP/1.1 200 OK\r\n") {
        t.Fatalf("unexpected response: %q", buf.String())
    }
}

func TestServerHTTPRejectsInvalidMethod(t *testing.T) {
    buf := bytes.NewBufferString("GET / HTTP/1.1\r\nContent-Length: 18446744073709551615\r\n\r\n")
    if err := acceptSSTPHTTP(buf); err == nil { t.Fatal("invalid method accepted") }
}

func TestServerRejectsSpoofedIP(t *testing.T) {
    client := netip.MustParseAddr("10.90.0.2")
    packet := make([]byte, 20)
    packet[0], packet[2], packet[3] = 0x45, 0, 20
    copy(packet[12:16], client.AsSlice())
    if !validClientPacket(packet, client, 1400) { t.Fatal("valid client packet rejected") }
    if validClientPacket(packet, netip.MustParseAddr("10.90.0.3"), 1400) {
        t.Fatal("spoofed packet accepted")
    }
    packet[3] = 19
    if validClientPacket(packet, client, 1400) { t.Fatal("invalid IP length accepted") }
}
