package httpapi

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	contractbackup "github.com/Asutorufa/yuhaiin/pkg/contract/backup"
	"github.com/Asutorufa/yuhaiin/pkg/security/secret"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
	"net/http"
)

// rpcHandler is the only handler shape used by new v2 endpoints. HTTP
// decoding, encoding and status handling stay at this boundary.
type rpcHandler[Request, Response any] func(context.Context, *Request) (*Response, error)

func addRPCRoute[Request, Response any](handlers *v2Handlers, endpoint v2Endpoint, handler rpcHandler[Request, Response]) {
	handlers.addOperation(endpoint, func(ctx context.Context, body []byte) (any, error) {
		if limit := v2RPCBodyLimits[endpoint]; limit > 0 && int64(len(body)) > limit {
			return nil, badRequest(errors.New("request is too large"))
		}
		var request Request
		if len(body) == 0 {
			body = []byte("{}")
		}
		if err := json.Unmarshal(body, &request); err != nil {
			return nil, badRequest(fmt.Errorf("decode request json failed: %w", err))
		}
		response, err := handler(ctx, &request)
		if err != nil {
			return nil, err
		}
		return redactResponse(ctx, response)
	})
	handlers.add(endpoint, func(w http.ResponseWriter, r *http.Request) error {
		if limit := v2RPCBodyLimits[endpoint]; limit > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		var request Request
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		response, err := handler(r.Context(), &request)
		if err != nil {
			return writeRPCError(w, err)
		}
		if capabilities, managed := secret.FromContext(r.Context()); managed && !capabilities.Reveal {
			response, err = secret.Redact(response)
			if err != nil {
				return writeError(w, http.StatusInternalServerError, "internal_error", "response redaction failed")
			}
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
	if errors.Is(err, secret.ErrAudit) {
		return &rpcError{status: http.StatusServiceUnavailable, code: "audit_unavailable", message: err.Error()}
	}
	if errors.Is(err, secret.ErrManage) || errors.Is(err, secret.ErrSecurity) || errors.Is(err, secret.ErrExecute) || errors.Is(err, secret.ErrAuthorization) || errors.Is(err, secret.ErrRetrieval) {
		return &rpcError{status: http.StatusForbidden, code: "permission_denied", message: err.Error()}
	}
	if errors.Is(err, secret.ErrPreserved) {
		return &rpcError{status: http.StatusConflict, code: "secret_reference_conflict", message: err.Error()}
	}
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
	if inUse, ok := errors.AsType[*plainstore.ResourceInUseError](err); ok {
		return writeJSON(w, http.StatusConflict, errorBody{Error: errorPayload{Code: "resource_in_use", Message: inUse.Error(), References: inUse.References}})
	}
	status, code, message := ErrorStatus(err)
	return writeError(w, status, code, message)
}

// ErrorStatus classifies an operation error exactly as the HTTP API reports
// it, so other transports (such as MCP) present the same result.
func ErrorStatus(err error) (status int, code, message string) {
	switch {
	case errors.Is(err, secret.ErrAudit):
		return http.StatusServiceUnavailable, "audit_unavailable", err.Error()
	case errors.Is(err, secret.ErrManage) || errors.Is(err, secret.ErrSecurity) || errors.Is(err, secret.ErrExecute) || errors.Is(err, secret.ErrAuthorization) || errors.Is(err, secret.ErrRetrieval):
		return http.StatusForbidden, "permission_denied", err.Error()
	case errors.Is(err, secret.ErrPreserved):
		return http.StatusConflict, "secret_reference_conflict", err.Error()
	case errors.Is(err, plainstore.ErrConflict):
		return http.StatusConflict, "conflict", err.Error()
	}
	if inUse, ok := errors.AsType[*plainstore.ResourceInUseError](err); ok {
		return http.StatusConflict, "resource_in_use", inUse.Error()
	}
	if rpcErr, ok := errors.AsType[*rpcError](err); ok {
		return rpcErr.status, rpcErr.code, rpcErr.message
	}
	return http.StatusInternalServerError, "internal_error", err.Error()
}

// redactResponse removes secrets from a response unless the request holds
// the explicit reveal capability, as the HTTP adapter does.
func redactResponse[Response any](ctx context.Context, response *Response) (any, error) {
	if capabilities, managed := secret.FromContext(ctx); managed && !capabilities.Reveal {
		redacted, err := secret.Redact(response)
		if err != nil {
			return nil, &rpcError{status: http.StatusInternalServerError, code: "internal_error", message: "response redaction failed"}
		}
		return redacted, nil
	}
	return response, nil
}

type emptyRequest struct{}
type emptyResponse struct{}
