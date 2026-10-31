package route

import (
	"context"
	"maps"
	"slices"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
)

type identityMatcher struct {
	kind    string
	ids     map[string]struct{}
	ordered []string
}

func newIdentityMatcher(kind string, ids []string) *identityMatcher {
	m := &identityMatcher{kind: kind, ids: make(map[string]struct{}, len(ids))}
	for _, id := range ids {
		if id != "" {
			m.ids[id] = struct{}{}
		}
	}
	m.ordered = slices.Sorted(maps.Keys(m.ids))
	return m
}

func (m *identityMatcher) Match(ctx context.Context, _ netapi.Address) bool {
	i := netapi.TrafficIdentity(ctx)
	matched, id := false, ""
	if i != nil && i.UserID != "" && i.CredentialID != "" && i.Valid() {
		switch m.kind {
		case "user":
			id = i.UserID
			_, matched = m.ids[id]
		case "credential":
			id = i.CredentialID
			_, matched = m.ids[id]
		case "group":
			// Membership is immutable and sorted at authentication, never read
			// from a database or resolved again on a packet path.
			if len(m.ordered) < len(i.GroupIDs) {
				for _, group := range m.ordered {
					if _, ok := slices.BinarySearch(i.GroupIDs, group); ok {
						id, matched = group, true
						break
					}
				}
				break
			}
			for _, group := range i.GroupIDs {
				if _, ok := m.ids[group]; ok {
					id = group
					matched = true
					break
				}
			}
		}
	}
	netapi.GetContext(ctx).AddConditionHistory(m.kind, id, m.kind, matched)
	return matched
}
