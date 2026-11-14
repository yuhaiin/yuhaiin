package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type networkAuditSender struct{ roots *x509.CertPool }
type auditDeliveryError string

func (e auditDeliveryError) Error() string { return string(e) }
func auditDeliveryReason(err error) string {
	if e, ok := errors.AsType[auditDeliveryError](err); ok {
		return string(e)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "delivery_timeout"
	}
	return "delivery_unavailable"
}
func (sender networkAuditSender) send(ctx context.Context, cfg auditConfiguration, records []AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validAuditSettings(cfg.AuditSettings) {
		return auditDeliveryError("delivery_configuration_invalid")
	}
	if cfg.Transport == "syslog-tls" {
		return sendAuditSyslog(ctx, cfg, records, sender.roots)
	}
	payload, err := json.Marshal(struct {
		InstanceID string        `json:"instanceId"`
		Events     []AuditRecord `json:"events"`
	}{cfg.InstanceID, records})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return auditDeliveryError("delivery_configuration_invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.token)
	}
	// No redirects, environment proxies, credentials in URL, or remote body logs.
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: sender.roots}, DisableKeepAlives: true, DialContext: auditDial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return auditDeliveryError("delivery_unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return auditDeliveryError("delivery_http_rejected")
	}
	return nil
}
func sendAuditSyslog(ctx context.Context, cfg auditConfiguration, records []AuditRecord, roots *x509.CertPool) error {
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return auditDeliveryError("delivery_configuration_invalid")
	}
	port := endpoint.Port()
	if port == "" {
		port = "6514"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	raw, err := auditDial(dialCtx, "tcp", net.JoinHostPort(endpoint.Hostname(), port))
	if err != nil {
		return auditDeliveryError("delivery_unavailable")
	}
	conn := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: endpoint.Hostname(), RootCAs: roots})
	if err := conn.HandshakeContext(dialCtx); err != nil {
		_ = raw.Close()
		return auditDeliveryError("delivery_unavailable")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err = conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	for _, record := range records {
		body, err := json.Marshal(struct {
			InstanceID string      `json:"instanceId"`
			Event      AuditRecord `json:"event"`
		}{cfg.InstanceID, record})
		if err != nil {
			return err
		}
		// RFC 5424 format with RFC 5425 octet counting. A successful socket write
		// confirms transport only, not collector persistence or processing.
		message := fmt.Sprintf("<134>1 %s - yuhaiin - security - %s", time.Unix(record.OccurredAt, 0).UTC().Format(time.RFC3339), body)
		if _, err = io.WriteString(conn, strconv.Itoa(len(message))+" "+message); err != nil {
			return auditDeliveryError("delivery_unavailable")
		}
	}
	return nil
}

// auditDial connects through Yuhaiin's dialer, so audit delivery is protected
// from Yuhaiin's own TUN like every other outbound socket.
func auditDial(ctx context.Context, network, address string) (net.Conn, error) {
	addr, err := netapi.ParseAddress(network, address)
	if err != nil {
		return nil, err
	}
	return dialer.DialHappyEyeballsv2(ctx, addr)
}
