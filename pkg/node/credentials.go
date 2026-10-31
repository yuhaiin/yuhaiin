package node

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/credential"
)

func (r *NodeRuntime) SetCredentialResolver(resolver credential.Resolver) {
	r.credentialMu.Lock()
	defer r.credentialMu.Unlock()
	r.credentials = resolver
}

func (r *NodeRuntime) InvalidateCredential(ref string) {
	r.credentialMu.Lock()
	var ids []string
	if r.selectors != nil {
		if snapshot := r.selectors.snapshot.Load(); snapshot != nil {
			for id, n := range snapshot.nodes {
				if nodeReferences(n, ref) {
					ids = append(ids, id)
				}
			}
		}
	}
	r.proxies.Range(func(id string, entry *ProxyEntry) bool {
		entry.mu.RLock()
		defer entry.mu.RUnlock()
		if !slices.Contains(ids, id) && entry.ContractConfig != nil && nodeReferences(*entry.ContractConfig, ref) {
			ids = append(ids, id)
		}
		return true
	})
	for _, id := range ids {
		r.cancelMeasurements(id)
		r.observer.invalidateHealth(id)
		r.proxies.Delete(id)
		delete(r.credentialVersions, id)
	}
	r.credentialMu.Unlock()
	if len(ids) > 0 && r.selectors != nil {
		s := r.selectors
		s.mu.Lock()
		s.nodeGenerations = r.observer.generations()
		s.prepareCircuits()
		s.scheduleLocked()
		s.rebuild(time.Now())
		s.mu.Unlock()
	}
}

func nodeReferences(node contractnode.Node, ref string) bool {
	var contains func(contractnode.Protocol) bool
	contains = func(p contractnode.Protocol) bool {
		if p.CredentialRef == ref {
			return true
		}
		if split := p.NetworkSplit; split != nil {
			return (split.TCP != nil && contains(*split.TCP)) || (split.UDP != nil && contains(*split.UDP))
		}
		return false
	}
	return slices.ContainsFunc(node.Chain, contains)
}

func (r *NodeRuntime) resolveCredentials(ctx context.Context, node contractnode.Node) (contractnode.Node, string, error) {
	if !slices.ContainsFunc(node.Chain, protocolHasCredential) {
		return node, "", nil
	}
	var revisions strings.Builder
	var resolve func(contractnode.Protocol) (contractnode.Protocol, error)
	resolve = func(p contractnode.Protocol) (contractnode.Protocol, error) {
		if p.CredentialRef != "" {
			if r.credentials == nil {
				return p, errors.New("outbound credential reference requires the identity module")
			}
			value, revision, err := r.credentials.Lookup(ctx, p.CredentialRef)
			if err != nil {
				return p, errors.New("outbound credential is unavailable")
			}
			_, _ = fmt.Fprintf(&revisions, "%s:%d;", p.CredentialRef, revision)
			return p.WithCredential(value)
		}
		if p.NetworkSplit != nil {
			split := *p.NetworkSplit
			p.NetworkSplit = &split
			for _, child := range []**contractnode.Protocol{&split.TCP, &split.UDP} {
				if *child != nil {
					resolved, err := resolve(**child)
					if err != nil {
						return p, err
					}
					*child = &resolved
				}
			}
		}
		return p, nil
	}
	node.Chain = slices.Clone(node.Chain)
	for i, p := range node.Chain {
		var err error
		node.Chain[i], err = resolve(p)
		if err != nil {
			return node, "", err
		}
	}
	return node, revisions.String(), nil
}

func protocolHasCredential(p contractnode.Protocol) bool {
	if p.CredentialRef != "" {
		return true
	}
	if s := p.NetworkSplit; s != nil {
		return (s.TCP != nil && protocolHasCredential(*s.TCP)) || (s.UDP != nil && protocolHasCredential(*s.UDP))
	}
	return false
}
