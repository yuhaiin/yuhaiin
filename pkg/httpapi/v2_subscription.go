package httpapi

import (
	"errors"
	"net/http"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func registerSubscriptionV2(register RegisterFunc, services V2Services) {
	register("GET /api/v2/subscriptions", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscriptions == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription store is unavailable")
		}
		resp, err := services.Subscriptions.ListLinks(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})

	register("PUT /api/v2/subscriptions", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscriptions == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription store is unavailable")
		}
		var req contractsubscription.LinkList
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Subscriptions.SaveLinks(r.Context(), req.Items, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("DELETE /api/v2/subscriptions", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscriptions == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription store is unavailable")
		}
		var req contractsubscription.LinkNames
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Subscriptions.DeleteLinks(r.Context(), req.Names); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("POST /api/v2/subscriptions/update", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscribe == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription controller is unavailable")
		}
		var req contractsubscription.LinkNames
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := services.Subscribe.Update(r.Context(), req.Names); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v2/publishes", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscriptions == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription store is unavailable")
		}
		resp, err := services.Subscriptions.ListPublishes(r.Context())
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})

	register("PUT /api/v2/publishes/{name}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscriptions == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription store is unavailable")
		}
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var req contractsubscription.Publish
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req.Name = name
		if err := services.Subscriptions.SavePublish(r.Context(), req, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("DELETE /api/v2/publishes/{name}", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscriptions == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription store is unavailable")
		}
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		err = services.Subscriptions.DeletePublish(r.Context(), name)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("POST /api/v2/publishes/{name}/resolve", func(w http.ResponseWriter, r *http.Request) error {
		if services.Subscribe == nil {
			return writeError(w, http.StatusServiceUnavailable, "unavailable", "subscription controller is unavailable")
		}
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var req contractsubscription.ResolvePublishRequest
		if err := readJSONBody(r, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Subscribe.ResolvePublish(r.Context(), name, req)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, resp)
	})
}
