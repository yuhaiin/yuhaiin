package httpapi

import (
	"context"
	"io"
	"net/http"
)

// Middleware is initialized after all management routes are registered. It can
// register its own routes and must guard the whole returned handler, including
// auxiliary routes. A non-nil closer is owned by the application's lifecycle.
// Initialization failure aborts startup rather than falling back to local access.
type Middleware func(context.Context, *http.ServeMux, MiddlewareOptions) (http.Handler, io.Closer, error)

type MiddlewareOptions struct {
	DataDirectory string
	AcceptOrigin  func(string, *http.Request) bool
}
