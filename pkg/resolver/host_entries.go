package resolver

import (
	"context"
	"errors"
	"fmt"
	"time"

	contractresolver "github.com/Asutorufa/yuhaiin/pkg/contract/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

func (c ContractConfigController) hostEntries() (contractresolver.HostEntries, error) {
	if c.resolver != nil {
		if store, ok := c.resolver.config.(contractresolver.HostEntries); ok {
			return store, nil
		}
	}
	return nil, errors.New("host entry store is unavailable")
}

func (c ContractConfigController) ListHostEntries(ctx context.Context, page, size int, query string) ([]contractresolver.HostEntry, int, error) {
	store, err := c.hostEntries()
	if err != nil {
		return nil, 0, err
	}
	return store.ListHostEntries(ctx, page, size, query)
}

func (c ContractConfigController) HostEntry(ctx context.Context, host string) (contractresolver.HostEntry, error) {
	store, err := c.hostEntries()
	if err != nil {
		return contractresolver.HostEntry{}, err
	}
	return store.HostEntry(ctx, host)
}

func (c ContractConfigController) SaveHostEntry(ctx context.Context, item contractresolver.HostEntry, create bool) (contractresolver.HostEntry, error) {
	store, err := c.hostEntries()
	if err != nil {
		return item, err
	}
	if err := item.Validate(); err != nil {
		return item, err
	}
	for _, addr := range []string{item.Host, item.Target} {
		if _, err := netapi.ParseAddress("", addr); err != nil {
			return item, fmt.Errorf("%w: address %q: %v", contractresolver.ErrInvalidHostEntry, addr, err)
		}
	}
	c.resolver.hostsMu.Lock()
	defer c.resolver.hostsMu.Unlock()
	saved, err := store.SaveHostEntry(ctx, item, create)
	if err != nil {
		return item, err
	}
	return saved, c.reloadHosts(ctx)
}

func (c ContractConfigController) DeleteHostEntry(ctx context.Context, host string) error {
	store, err := c.hostEntries()
	if err != nil {
		return err
	}
	c.resolver.hostsMu.Lock()
	defer c.resolver.hostsMu.Unlock()
	if err := store.DeleteHostEntry(ctx, host); err != nil {
		return err
	}
	return c.reloadHosts(ctx)
}

func (c ContractConfigController) reloadHosts(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	// Only activation needs the full runtime index. Directory RPCs never load it.
	snapshot, err := c.resolver.config.Hosts(ctx)
	if err != nil {
		return fmt.Errorf("host mapping saved, but runtime reload failed: %w", err)
	}
	if c.resolver.hosts != nil {
		c.resolver.hosts.Apply(snapshot.Hosts)
	}
	return nil
}
