package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type userPutRequest struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Enabled    bool                     `json:"enabled"`
	Usage      contractuser.Usage       `json:"usage"`
	Credential *contractuser.Credential `json:"credential,omitzero"`
}

func addUserRPCRoutesV2(handlers *v2Handlers, services V2Services) {
	api := v2API{services: services}
	addRPCRoute(handlers, v2UsersGet, api.users)
	addRPCRoute(handlers, v2UsersPost, api.createUser)
	addRPCRoute(handlers, v2UserGet, api.user)
	addRPCRoute(handlers, v2UserPut, api.saveUser)
	addRPCRoute(handlers, v2UserDelete, api.deleteUser)
}

func (a v2API) users(ctx context.Context, request *listRequest) (*listV2[contractuser.UserView], error) {
	if a.services.Users == nil {
		return nil, unavailable("user store is unavailable")
	}
	items, err := a.services.Users.List(ctx)
	if err != nil {
		return nil, err
	}
	query := strings.ToLower(strings.TrimSpace(request.Query))
	if query != "" {
		filtered := items[:0]
		for _, item := range items {
			if strings.Contains(strings.ToLower(item.ID), query) || strings.Contains(strings.ToLower(item.Name), query) || strings.Contains(strings.ToLower(string(item.Credential.Type)), query) {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	return pageResponse(items, request), nil
}

func (a v2API) createUser(ctx context.Context, request *contractuser.UserWrite) (*contractuser.UserView, error) {
	if a.services.Users == nil {
		return nil, unavailable("user store is unavailable")
	}
	value, err := a.services.Users.Create(ctx, *request)
	if err != nil {
		return nil, badRequest(err)
	}
	if a.services.Auth != nil {
		if err := a.services.Auth.Reload(ctx); err != nil {
			return nil, err
		}
	}
	return &value, nil
}

func (a v2API) user(ctx context.Context, request *idRequest) (*contractuser.UserView, error) {
	if a.services.Users == nil {
		return nil, unavailable("user store is unavailable")
	}
	value, err := a.services.Users.Get(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	if err != nil {
		return nil, err
	}
	view := value.View()
	return &view, nil
}

func (a v2API) saveUser(ctx context.Context, request *userPutRequest) (*contractuser.UserView, error) {
	if a.services.Users == nil {
		return nil, unavailable("user store is unavailable")
	}
	value, err := a.services.Users.Get(ctx, request.ID)
	if errors.Is(err, plainstore.ErrNotFound) {
		return nil, notFound(err)
	}
	if err != nil {
		return nil, err
	}
	value.Name = request.Name
	value.Enabled = request.Enabled
	value.Usage = request.Usage
	if request.Credential != nil {
		value.Credential = *request.Credential
	}
	if err := value.Validate(); err != nil {
		return nil, badRequest(err)
	}
	if err := a.services.Users.Save(ctx, value, time.Now().Unix()); err != nil {
		return nil, badRequest(err)
	}
	if a.services.Auth != nil {
		if err := a.services.Auth.Reload(ctx); err != nil {
			return nil, err
		}
	}
	view := value.View()
	return &view, nil
}

func (a v2API) deleteUser(ctx context.Context, request *idRequest) (*emptyResponse, error) {
	if a.services.Users == nil {
		return nil, unavailable("user store is unavailable")
	}
	if err := a.services.Users.Delete(ctx, request.ID); err != nil {
		if errors.Is(err, plainstore.ErrNotFound) {
			return nil, notFound(err)
		}
		if errors.Is(err, plainstore.ErrUserReferenced) {
			return nil, &rpcError{status: http.StatusConflict, code: "user_referenced", message: err.Error()}
		}
		return nil, badRequest(err)
	}
	if a.services.Auth != nil {
		if err := a.services.Auth.Reload(ctx); err != nil {
			return nil, err
		}
	}
	return &emptyResponse{}, nil
}
