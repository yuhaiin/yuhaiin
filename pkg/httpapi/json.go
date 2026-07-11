package httpapi

import (
	json "encoding/json/v2"
	"fmt"
	"net/http"
)

type errorBody struct {
	Error errorPayload `json:"error"`
}

type errorPayload struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if status == http.StatusNoContent {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if v == nil {
		v = struct{}{}
	}

	if err := json.MarshalWrite(w, v); err != nil {
		return fmt.Errorf("encode json response failed: %w", err)
	}

	return nil
}

func writeError(w http.ResponseWriter, status int, code, message string) error {
	return writeJSON(w, status, errorBody{
		Error: errorPayload{
			Code:    code,
			Message: message,
		},
	})
}

func readJSONBody(r *http.Request, v any) error {
	if err := json.UnmarshalRead(r.Body, v); err != nil {
		return fmt.Errorf("decode request json failed: %w", err)
	}
	return nil
}
