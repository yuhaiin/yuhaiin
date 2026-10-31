package httpapi

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/contract/node"
	runtimenode "github.com/Asutorufa/yuhaiin/pkg/node"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
)

func (a v2API) commitNodeImport(ctx context.Context, request *node.ImportCommit) (*node.ImportResults, error) {
	if a.services.Node == nil {
		return nil, unavailable("node controller is unavailable")
	}
	items, indices, err := runtimenode.PrepareImportCommit(*request)
	if err != nil {
		return nil, badRequest(err)
	}
	result := &node.ImportResults{Items: make([]node.ImportResult, 0, len(indices))}
	for _, i := range indices {
		value, err := secret.Merge(ctx, items[i], node.Node{})
		if err == nil {
			_, err = a.services.Node.Save(ctx, value)
		}
		status := node.ImportResult{Index: i, ID: items[i].ID, Saved: err == nil}
		if err != nil {
			switch {
			case errors.Is(err, secret.ErrManage), errors.Is(err, secret.ErrSecurity), errors.Is(err, secret.ErrExecute), errors.Is(err, secret.ErrAuthorization):
				status.Error = err.Error()
			default:
				status.Error = "node could not be saved"
			}
		}
		result.Items = append(result.Items, status)
	}
	return result, nil
}
