//go:build (((linux && !android) || darwin) && (amd64 || arm64)) || (windows && amd64) || (android && arm64 && cgo)

package zerotier

import (
	"net/netip"
	"testing"

	zt "github.com/yuhaiin/zerotier-go"
)

func TestApplyConfigIgnoresQueuedConfigAfterClose(t *testing.T) {
	closing := make(chan struct{})
	close(closing)
	client := &Client{closing: closing}
	client.applyConfig(zt.NetworkConfig{
		ID: 1, MAC: 1, Status: zt.NetworkOK, Operation: zt.NetworkUp, MTU: 1400,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
	})
	if client.active != nil {
		t.Fatal("network configuration installed a session after close started")
	}
}

func TestInstallSessionRejectsSessionAfterClose(t *testing.T) {
	closing := make(chan struct{})
	close(closing)
	client := &Client{closing: closing}

	if old, installed := client.installSession(&session{}); installed || old != nil {
		t.Fatal("session was installed after close started")
	}
	if client.active != nil {
		t.Fatal("active session changed after close started")
	}
}
