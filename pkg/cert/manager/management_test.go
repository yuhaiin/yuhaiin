package manager

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
	"uuid"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func TestManagementBindingRequiresMaterialAndHotUpdates(t *testing.T) {
	ca := newTestCA(t)
	cfg := ca.config()
	store := managerStore(t)
	resource, err := store.Save(t.Context(), cfg, 0)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(Options{Store: store, Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		return certificates.Material{}, errors.New("not scheduled")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if _, _, err := manager.BindManagement(t.Context(), cfg.ID); err == nil {
		t.Fatal("unissued certificate bound management")
	}
	if refs, err := store.References(t.Context(), cfg.ID); err != nil || len(refs) != 0 {
		t.Fatal("failed binding left a guard", refs, err)
	}
	publish := func(serial int64) {
		t.Helper()
		now := time.Now()
		material := signedMaterial(t, ca, cfg, now, serial)
		owner := uuid.New().String()
		if ok, err := store.Acquire(t.Context(), cfg.ID, resource.Revision, owner, now, time.Minute); err != nil || !ok {
			t.Fatal(ok, err)
		}
		if err := store.Complete(t.Context(), cfg.ID, resource.Revision, owner, now, contract.Status{State: "ready"}, &material); err != nil {
			t.Fatal(err)
		}
		if err := manager.Cache.Reload(t.Context(), now); err != nil {
			t.Fatal(err)
		}
	}
	publish(2)
	config, pair, err := manager.BindManagement(t.Context(), cfg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(t.Context(), cfg.ID, resource.Revision); !errors.Is(err, certificates.ErrInUse) {
		t.Fatal("bound resource was deleted", err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var workers netWorkers
	defer func() { _ = listener.Close(); workers.close() }()
	workers.serve(listener)
	roots := x509.NewCertPool()
	roots.AddCert(ca.root)
	dial := func(name string) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: name, MinVersion: tls.VersionTLS12})
	}
	original, err := dial("site.example")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	if !bytes.Equal(original.ConnectionState().PeerCertificates[0].Raw, pair.Certificate[0]) {
		t.Fatal("wrong initial certificate")
	}
	if err := original.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	publish(3)
	replacement, err := dial("site.example")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if bytes.Equal(replacement.ConnectionState().PeerCertificates[0].Raw, pair.Certificate[0]) {
		t.Fatal("renewal did not reach management listener")
	}
	if _, err := original.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	value := make([]byte, len("still alive"))
	if _, err := io.ReadFull(original, value); err != nil || string(value) != "still alive" {
		t.Fatal("renewal interrupted old stream", err)
	}
	if connection, err := dial("wrong.example"); err == nil {
		connection.Close()
		t.Fatal("wrong SNI accepted")
	}
	if _, _, err := manager.BindManagement(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(t.Context(), cfg.ID, resource.Revision); err != nil {
		t.Fatal("explicit host mode did not release reference", err)
	}
}

type netWorkers struct {
	group  sync.WaitGroup
	cancel context.CancelFunc
}

func (w *netWorkers) serve(listener net.Listener) {
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.group.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			w.group.Go(func() {
				defer conn.Close()
				stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
				defer stop()
				_, _ = io.Copy(conn, conn)
			})
		}
	})
}
func (w *netWorkers) close() { w.cancel(); w.group.Wait() }
