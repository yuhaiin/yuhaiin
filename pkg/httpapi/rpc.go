package httpapi

import (
	"context"
	"errors"
	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
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
	if errors.Is(err, contractbackup.ErrBusy) {
		return &rpcError{status: http.StatusConflict, code: "backup_busy", message: err.Error()}
	}
	if errors.Is(err, plainstore.ErrConflict) {
		return &rpcError{status: http.StatusConflict, code: "conflict", message: err.Error()}
	}
	return &rpcError{status: http.StatusBadRequest, code: "bad_request", message: err.Error()}
}

func unavailable(message string) error {
	return &rpcError{status: http.StatusServiceUnavailable, code: "unavailable", message: message}
}

func notFound(err error) error {
	return &rpcError{status: http.StatusNotFound, code: "not_found", message: err.Error()}
}

func writeRPCError(w http.ResponseWriter, err error) error {
	if errors.Is(err, plainstore.ErrConflict) {
		return writeError(w, http.StatusConflict, "conflict", err.Error())
	}
	if inUse, ok := errors.AsType[*plainstore.ResourceInUseError](err); ok {
		return writeJSON(w, http.StatusConflict, errorBody{Error: errorPayload{Code: "resource_in_use", Message: inUse.Error(), References: inUse.References}})
	}
	if rpcErr, ok := errors.AsType[*rpcError](err); ok {
		return writeError(w, rpcErr.status, rpcErr.code, rpcErr.message)
	}
	return writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
}

type emptyRequest struct{}
type emptyResponse struct{}
