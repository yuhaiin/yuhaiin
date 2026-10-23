package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
)

func TestQueuedDNSDatagramCompletesOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	agent := &dnsServer{ctx: ctx, cancel: cancel, reqBuffer: ringbuffer.NewRingBuffer[*netapi.DNSRawRequest](8, func() int { return 8 }), notifyChan: make(chan struct{}, 1)}
	packet := netapi.NewPacket(&net.UDPAddr{}, netapi.EmptyAddr, pool.Clone([]byte{0}), nil)
	done := make(chan error, 2)
	if err := agent.DoDatagram(t.Context(), &netapi.DNSRawRequest{Question: packet, Done: func(err error) { done <- err }}); err != nil {
		packet.DecRef()
		t.Fatal(err)
	}
	packet.DecRef()
	if err := agent.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("completion=%v", err)
		}
	default:
		t.Fatal("queued request was not completed")
	}
	select {
	case err := <-done:
		t.Fatalf("duplicate completion: %v", err)
	default:
	}
}

func TestAcceptedDNSDatagramCompletesEvenWhenMalformed(t *testing.T) {
	agent := NewServer("", netapi.ErrorResolver(nil))
	defer agent.Close()
	packet := netapi.NewPacket(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}, netapi.EmptyAddr, pool.Clone([]byte{0}), netapi.WriteBackFunc(func([]byte, net.Addr) (int, error) { t.Error("malformed DNS produced a reply"); return 0, nil }))
	done := make(chan error, 2)
	if err := agent.DoDatagram(t.Context(), &netapi.DNSRawRequest{Question: packet, Done: func(err error) { done <- err }}); err != nil {
		packet.DecRef()
		t.Fatal(err)
	}
	packet.DecRef()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("missing parse error")
		}
	case <-time.After(time.Second):
		t.Fatal("accepted DNS request never completed")
	}
	select {
	case err := <-done:
		t.Logf("duplicate completion error: %v", err)
		t.Fatal("completion called twice")
	default:
	}
}
