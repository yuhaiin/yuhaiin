package statistics

import (
	"context"
	"net"
	"sync/atomic"

	contractconnection "github.com/Asutorufa/yuhaiin/pkg/contract/connection"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

// LocalUsage covers locally served traffic that never reaches Connections.
// It is used for DNS only; ordinary forwarding reuses existing counters.
type LocalUsage struct {
	upload, download atomic.Uint64
	session          *usageSession
}

func (l *LocalUsage) LoadUpload() uint64   { return l.upload.Load() }
func (l *LocalUsage) LoadDownload() uint64 { return l.download.Load() }
func (l *LocalUsage) AddUpload(n int) {
	if l != nil && n > 0 {
		l.upload.Add(uint64(n))
	}
}
func (l *LocalUsage) AddDownload(n int) {
	if l != nil && n > 0 {
		l.download.Add(uint64(n))
	}
}
func (l *LocalUsage) Close() {
	if l != nil {
		l.session.end()
	}
}

// Finish also captures errors from asynchronous local DNS handling.
func (l *LocalUsage) Finish(err error) {
	if l != nil {
		l.session.fail(err)
		l.Close()
	}
}

func (r *UserUsage) Local(info contractconnection.Connection, identity context.Context) *LocalUsage {
	if r == nil {
		return nil
	}
	observation := new(LocalUsage)
	observation.session = r.register(info, observation, identity)
	if observation.session == nil {
		return nil
	}
	return observation
}

type localUsageConn struct {
	net.Conn
	observation *LocalUsage
}

func (c *localUsageConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.observation.AddUpload(n)
	return n, err
}
func (c *localUsageConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.observation.AddDownload(n)
	return n, err
}
func (c *localUsageConn) Close() error { err := c.Conn.Close(); c.observation.Close(); return err }

func (l *LocalUsage) Conn(raw net.Conn) net.Conn {
	if l == nil {
		return raw
	}
	return &localUsageConn{Conn: raw, observation: l}
}

// Locally handled Gateway actions never dial an outbound. Keep their access
// decisions in the audit without inventing forwarded bytes or TCP sessions.
func (c *Connections) RecordGatewayAction(ctx *netapi.Context, target string, blocked bool) {
	if c.userUsage == nil {
		return
	}
	address, err := netapi.ParseAddress("tcp", target)
	if err != nil {
		return
	}
	info := c.getConnection(ctx, nil, address, 0)
	info.NodeID, info.NodeName, info.Mode = "@local-gateway", "Local gateway", "gateway"
	result, reason := "closed", "gateway_response"
	if blocked {
		result, reason = "rejected", "gateway_rejected"
	}
	c.userUsage.event(info, result, reason)
}
