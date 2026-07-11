package httpapi

import (
	"context"
	"errors"
	"net/http"
)

// rpcHandler is the only handler shape used by new v2 endpoints. HTTP
// decoding, encoding and status handling stay at this boundary.
type rpcHandler[Request, Response any] func(context.Context, *Request) (*Response, error)

func addRPCRoute[Request, Response any](handlers *v2Handlers, endpoint v2Endpoint, handler rpcHandler[Request, Response]) {
	handlers.add(endpoint, func(w http.ResponseWriter, r *http.Request) error {
		var request Request
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		response, err := handler(r.Context(), &request)
		if err != nil {
			return writeRPCError(w, err)
		}
		return writeJSON(w, http.StatusOK, response)
	})
}

type rpcError struct {
	status  int
	code    string
	message string
}

func (e *rpcError) Error() string { return e.message }

func badRequest(err error) error {
	return &rpcError{status: http.StatusBadRequest, code: "bad_request", message: err.Error()}
}

func unavailable(message string) error {
	return &rpcError{status: http.StatusServiceUnavailable, code: "unavailable", message: message}
}

func notFound(err error) error {
	return &rpcError{status: http.StatusNotFound, code: "not_found", message: err.Error()}
}

func writeRPCError(w http.ResponseWriter, err error) error {
	var rpcErr *rpcError
	if errors.As(err, &rpcErr) {
		return writeError(w, rpcErr.status, rpcErr.code, rpcErr.message)
	}
	return writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
}

type emptyRequest struct{}
type emptyResponse struct{}
