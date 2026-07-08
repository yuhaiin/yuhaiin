package httpapi

import (
	"fmt"
	"net/http"
)

func writeJSONResponse(w http.ResponseWriter, status int, m any) error {
	if status == http.StatusNoContent {
		return writeJSON(w, status, nil)
	}

	if err := writeJSON(w, status, m); err != nil {
		return fmt.Errorf("write response json failed: %w", err)
	}

	return nil
}

func readJSONRequestBody(r *http.Request, v any) error {
	if err := readJSONBody(r, v); err != nil {
		return fmt.Errorf("decode request json failed: %w", err)
	}

	return nil
}
