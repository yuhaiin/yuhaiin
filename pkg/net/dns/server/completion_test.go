package server

import (
	"context"
	"errors"
	"net"
	"testing"

	"codeberg.org/miekg/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/dns/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/ringbuffer"
	"github.com/Asutorufa/yuhaiin/pkg/utils/semaphore"
)

func TestQueuedDNSDatagramCompletesOnShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	agent := &dnsServer{ctx: ctx, cancel: cancel, reqBuffer: ringbuffer.NewRingBuffer[*queuedRequest](8, func() int { return 8 }), notifyChan: make(chan struct{}, 1), resolver: resolver.NewClient(resolver.Config{}, resolver.TransportFunc(func(context.Context, *resolver.Request) (*dns.Msg, error) {
		t.Fatal("queued request reached upstream")
		return nil, nil
	})), udpSemaphore: semaphore.NewSemaphore(1)}
	defer agent.resolver.Close()
	packet := netapi.NewPacket(&net.UDPAddr{}, netapi.EmptyAddr, pool.Clone(admissionQuery(t, "queued.example.")), nil)
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

func TestMalformedDNSDatagramRemainsCallerOwned(t *testing.T) {
	agent := NewServer("", netapi.ErrorResolver(nil))
	defer agent.Close()
	packet := netapi.NewPacket(&net.UDPAddr{}, netapi.EmptyAddr, pool.Clone([]byte{0}), nil)
	defer packet.DecRef()
	called := false
	err := agent.DoDatagram(t.Context(), &netapi.DNSRawRequest{Question: packet, Done: func(error) { called = true }})
	if err == nil || called {
		t.Fatalf("malformed admission: err=%v completion=%t", err, called)
	}
}
