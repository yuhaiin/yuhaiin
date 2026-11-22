package httpapi

import (
	"context"
	"errors"
	"net/http"

	managementpermission "github.com/Asutorufa/yuhaiin/pkg/management/permission"
)

// Operations exposes the v2 RPC actions independently of HTTP. The HTTP
// adapter and other resource servers (such as MCP) run the same handlers, with
// the same request and response DTOs, permissions and secret redaction; no
// transport re-implements business logic or calls the API over loopback.
type Operations struct {
	handlers *v2Handlers
}

// NewOperations builds the operation set for services.
func NewOperations(services V2Services) *Operations {
	return &Operations{handlers: newV2Handlers(services)}
}

// ErrUnknownOperation is returned for names that are not RPC operations.
var ErrUnknownOperation = errors.New("unknown operation")

// Permission returns the permission required by the named operation. Stream
// endpoints are not operations.
func (o *Operations) Permission(name string) (managementpermission.Permission, bool) {
	endpoint := v2Endpoint(name)
	if _, ok := o.handlers.operations[endpoint]; !ok || isV2StreamEndpoint(endpoint) {
		return "", false
	}
	permission, ok := v2Permissions[endpoint]
	return permission, ok && permission != ""
}

// Invoke runs the named operation with a JSON request body. It enforces the
// operation's permission against the principal recorded in ctx, so a caller
// cannot skip authorization by choosing a different transport.
func (o *Operations) Invoke(ctx context.Context, name string, request []byte) (any, error) {
	permission, ok := o.Permission(name)
	if !ok {
		return nil, ErrUnknownOperation
	}
	if !managementpermission.Allowed(ctx, permission) {
		return nil, &rpcError{status: http.StatusForbidden, code: "permission_denied", message: "missing permission " + string(permission)}
	}
	return o.handlers.operations[v2Endpoint(name)](ctx, request)
}

// RegisterOperations registers the HTTP routes of ops.
func RegisterOperations(register RegisterFunc, ops *Operations) {
	// Cross-origin JSON RPC clients send an OPTIONS preflight because they use
	// Content-Type: application/json and may include Authorization. ServeMux
	// otherwise answers 405 since the actual endpoints are POST-only.
	register("OPTIONS /api/v2/rpc/", func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusNoContent)
		return nil
	})
	for _, route := range v2Routes {
		register(v2RoutePattern(route), ops.handlers.handler(route.endpoint))
	}
}
