package httpapi

import (
	"errors"
	"net/http"

	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func registerSubscriptionV2(register RegisterFunc, services V2Services) {
	const storeUnavailable = "subscription store is unavailable"
	const controllerUnavailable = "subscription controller is unavailable"

	registerV2Get(register, "GET /api/v2/subscriptions", services.Subscriptions, storeUnavailable, func(store *plainstore.SubscriptionStore, r *http.Request) (contractsubscription.LinkList, error) {
		return store.ListLinks(r.Context())
	})
	registerV2Service(register, "PUT /api/v2/subscriptions", services.Subscriptions, storeUnavailable, func(store *plainstore.SubscriptionStore, w http.ResponseWriter, r *http.Request) error {
		var request contractsubscription.LinkList
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := store.SaveLinks(r.Context(), request.Items, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	registerV2Service(register, "DELETE /api/v2/subscriptions", services.Subscriptions, storeUnavailable, func(store *plainstore.SubscriptionStore, w http.ResponseWriter, r *http.Request) error {
		var request contractsubscription.LinkNames
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := store.DeleteLinks(r.Context(), request.Names); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	registerV2Service(register, "POST /api/v2/subscriptions/update", services.Subscribe, controllerUnavailable, func(service SubscriptionController, w http.ResponseWriter, r *http.Request) error {
		var request contractsubscription.LinkNames
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if err := service.Update(r.Context(), request.Names); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	registerV2Get(register, "GET /api/v2/publishes", services.Subscriptions, storeUnavailable, func(store *plainstore.SubscriptionStore, r *http.Request) (contractsubscription.PublishList, error) {
		return store.ListPublishes(r.Context())
	})
	registerV2Service(register, "PUT /api/v2/publishes/{name}", services.Subscriptions, storeUnavailable, func(store *plainstore.SubscriptionStore, w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var request contractsubscription.Publish
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		request.Name = name
		if err := store.SavePublish(r.Context(), request, 0); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	registerV2Service(register, "DELETE /api/v2/publishes/{name}", services.Subscriptions, storeUnavailable, func(store *plainstore.SubscriptionStore, w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		err = store.DeletePublish(r.Context(), name)
		if errors.Is(err, plainstore.ErrNotFound) {
			return writeError(w, http.StatusNotFound, "not_found", err.Error())
		}
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	registerV2Service(register, "POST /api/v2/publishes/{name}/resolve", services.Subscribe, controllerUnavailable, func(service SubscriptionController, w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var request contractsubscription.ResolvePublishRequest
		if err := readJSONBody(r, &request); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		response, err := service.ResolvePublish(r.Context(), name, request)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		return writeJSON(w, http.StatusOK, response)
	})
}
