package httpapi

import (
	"net/http"

	"github.com/Asutorufa/yuhaiin/pkg/control"
)

func RuntimeInfo(runtime control.Runtime) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		info, err := runtime.BuildInfo(r.Context())
		if err != nil {
			return err
		}

		return writeJSON(w, http.StatusOK, info)
	}
}
