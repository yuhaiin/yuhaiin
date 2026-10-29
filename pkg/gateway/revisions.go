package gateway

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
	"github.com/Asutorufa/yuhaiin/pkg/store"
)

// Entity revisions are checked as well as the enclosing config revision. A
// visual editor can detect an obsolete item without overwriting another edit.
func advanceRevisions[T any](old, next []T) ([]T, error) {
	type identity struct {
		ID       string `json:"id"`
		Revision uint64 `json:"revision"`
	}
	type previous struct {
		data     []byte
		identity identity
	}
	prior := make(map[string]previous, len(old))
	for _, item := range old {
		data, err := json.Marshal(item, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		var id identity
		if err := json.Unmarshal(data, &id); err != nil {
			return nil, err
		}
		prior[id.ID] = previous{data, id}
	}
	result := make([]T, 0, len(next))
	for _, item := range next {
		data, err := json.Marshal(item, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		var id identity
		if err := json.Unmarshal(data, &id); err != nil {
			return nil, err
		}
		p, exists := prior[id.ID]
		if id.Revision != p.identity.Revision {
			return nil, fmt.Errorf("%w: resource %s", store.ErrConflict, id.ID)
		}
		if exists && bytes.Equal(data, p.data) {
			result = append(result, item)
			continue
		}
		var fields map[string]jsontext.Value
		if err := json.Unmarshal(data, &fields); err != nil {
			return nil, err
		}
		fields["revision"], err = json.Marshal(id.Revision + 1)
		if err != nil {
			return nil, err
		}
		data, err = json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(data, &item); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func reviseConfig(old, next contract.Config) (contract.Config, error) {
	var err error
	// Old clients do not know the import safety marker. Preserve it on disabled
	// Gateways until an administrator explicitly enables the repaired Gateway.
	next.Gateways = contract.PreserveDisabledGuards(old.Gateways, next.Gateways)
	if next.Gateways, err = advanceRevisions(old.Gateways, next.Gateways); err != nil {
		return next, err
	}
	if next.Rules, err = advanceRevisions(old.Rules, next.Rules); err != nil {
		return next, err
	}
	if next.Upstreams, err = advanceRevisions(old.Upstreams, next.Upstreams); err != nil {
		return next, err
	}
	if next.FilterLists, err = advanceRevisions(old.FilterLists, next.FilterLists); err != nil {
		return next, err
	}
	return next, nil
}
