package httpapi

import (
	"context"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/control"
	schemaapi "github.com/Asutorufa/yuhaiin/pkg/schema/api"
	schemabackup "github.com/Asutorufa/yuhaiin/pkg/schema/backup"
	schemaconfig "github.com/Asutorufa/yuhaiin/pkg/schema/config"
	schemanode "github.com/Asutorufa/yuhaiin/pkg/schema/node"
	schematools "github.com/Asutorufa/yuhaiin/pkg/schema/tools"
)

type Services struct {
	Config      control.ConfigPort
	Lists       control.ListsPort
	Rules       control.RulesPort
	Inbound     control.InboundPort
	Resolver    control.ResolverPort
	Node        control.NodePort
	Subscribe   control.SubscribePort
	Tag         control.TagPort
	Connections control.ConnectionsPort
	Tools       control.ToolsPort
	Backup      control.BackupPort
}

type RegisterFunc func(pattern string, handler func(http.ResponseWriter, *http.Request) error)

func RegisterV1(register RegisterFunc, services Services) {
	runtime := control.RuntimeAdapter{Config: services.Config}
	traffic := control.TrafficAdapter{Connections: services.Connections}

	register("GET /api/v1/info", RuntimeInfo(runtime))
	register("GET /api/v1/config", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Config.Load(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/config", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaconfig.Setting{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Config.Save(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/lists", func(w http.ResponseWriter, r *http.Request) error {
		if hasPageQuery(r) {
			req, err := pageRequestFromQuery(r)
			if err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
			resp, err := services.Lists.ListPage(r.Context(), req)
			if err != nil {
				return err
			}
			return writeJSON(w, http.StatusOK, resp)
		}

		resp, err := services.Lists.List(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/lists/config", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Lists.List(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp.GetRefreshConfig())
	})
	register("PUT /api/v1/lists/config", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.SaveListConfigRequest{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Lists.SaveConfig(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("POST /api/v1/lists:refresh", func(w http.ResponseWriter, r *http.Request) error {
		if _, err := services.Lists.Refresh(r.Context(), &schemaapi.Empty{}); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("GET /api/v1/lists/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Lists.Get(r.Context(), schemaapi.String(name))
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/lists/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemaconfig.List{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req.SetName(name)
		if _, err := services.Lists.Save(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("DELETE /api/v1/lists/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Lists.Remove(r.Context(), schemaapi.String(name)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/rules", func(w http.ResponseWriter, r *http.Request) error {
		if hasPageQuery(r) {
			req, err := pageRequestFromQuery(r)
			if err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
			resp, err := services.Rules.ListPage(r.Context(), req)
			if err != nil {
				return err
			}
			return writeJSON(w, http.StatusOK, resp)
		}

		resp, err := services.Rules.List(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/rules/config", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Rules.Config(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/rules/config", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaconfig.Configv2{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Rules.SaveConfig(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("POST /api/v1/rules:change-priority", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.ChangePriorityRequest{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Rules.ChangePriority(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("POST /api/v1/rules:test", func(w http.ResponseWriter, r *http.Request) error {
		req := schemaapi.String("")
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Rules.Test(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/rules/block-history", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Rules.BlockHistory(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/rules/{name}/{index}", func(w http.ResponseWriter, r *http.Request) error {
		idx, err := ruleIndexFromPath(r)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Rules.Get(r.Context(), idx)
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/rules/{name}/{index}", func(w http.ResponseWriter, r *http.Request) error {
		idx, err := ruleIndexFromPath(r)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		rule := &schemaconfig.Rulev2{}
		if err := readJSONRequestBody(r, rule); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemaapi.RuleSaveRequest{}
		req.SetIndex(idx)
		req.SetRule(rule)
		if _, err := services.Rules.Save(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("DELETE /api/v1/rules/{name}/{index}", func(w http.ResponseWriter, r *http.Request) error {
		idx, err := ruleIndexFromPath(r)
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Rules.Remove(r.Context(), idx); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/inbounds", func(w http.ResponseWriter, r *http.Request) error {
		if hasPageQuery(r) {
			req, err := pageRequestFromQuery(r)
			if err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
			resp, err := services.Inbound.ListPage(r.Context(), req)
			if err != nil {
				return err
			}
			return writeJSON(w, http.StatusOK, resp)
		}

		resp, err := services.Inbound.List(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("POST /api/v1/inbounds:apply", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.InboundsResponse{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Inbound.Apply(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("GET /api/v1/inbounds/platform-info", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Inbound.PlatformInfo(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/inbounds/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Inbound.Get(r.Context(), schemaapi.String(name))
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return writeError(w, http.StatusNotFound, "not_found", err.Error())
			}
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/inbounds/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemaconfig.Inbound{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req.SetName(name)
		resp, err := services.Inbound.Save(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("DELETE /api/v1/inbounds/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Inbound.Remove(r.Context(), schemaapi.String(name)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/resolvers", func(w http.ResponseWriter, r *http.Request) error {
		if hasPageQuery(r) {
			req, err := pageRequestFromQuery(r)
			if err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
			resp, err := services.Resolver.ListPage(r.Context(), req)
			if err != nil {
				return err
			}
			return writeJSON(w, http.StatusOK, resp)
		}

		resp, err := services.Resolver.List(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/resolver/hosts", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Resolver.Hosts(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/resolver/hosts", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.Hosts{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Resolver.SaveHosts(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("GET /api/v1/resolver/fakedns", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Resolver.Fakedns(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/resolver/fakedns", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaconfig.FakednsConfig{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Resolver.SaveFakedns(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("GET /api/v1/resolver/server", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Resolver.Server(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, map[string]string{"name": resp.GetValue()})
	})
	register("PUT /api/v1/resolver/server", func(w http.ResponseWriter, r *http.Request) error {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.UnmarshalRead(r.Body, &req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("decode request json failed: %v", err))
		}
		if _, err := services.Resolver.SaveServer(r.Context(), schemaapi.String(req.Name)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("GET /api/v1/resolvers/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Resolver.Get(r.Context(), schemaapi.String(name))
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/resolvers/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resolver := &schemaconfig.Dns{}
		if err := readJSONRequestBody(r, resolver); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemaapi.SaveResolver{}
		req.SetName(name)
		req.SetResolver(resolver)
		resp, err := services.Resolver.Save(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("DELETE /api/v1/resolvers/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Resolver.Remove(r.Context(), schemaapi.String(name)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/nodes", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Node.List(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/nodes/selected", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Node.Now(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/nodes/active", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Node.Activates(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("POST /api/v1/nodes:latency", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemanode.Requests{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Node.Latency(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("POST /api/v1/nodes", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemanode.Point{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Node.Save(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("POST /api/v1/nodes/{hash}/use", func(w http.ResponseWriter, r *http.Request) error {
		hash, err := requiredPathValue(r, "hash")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemaapi.UseReq{}
		req.SetHash(hash)
		resp, err := services.Node.Use(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("POST /api/v1/nodes/{hash}/close", func(w http.ResponseWriter, r *http.Request) error {
		hash, err := requiredPathValue(r, "hash")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Node.Close(r.Context(), schemaapi.String(hash)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("GET /api/v1/nodes/{hash}", func(w http.ResponseWriter, r *http.Request) error {
		hash, err := requiredPathValue(r, "hash")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		resp, err := services.Node.Get(r.Context(), schemaapi.String(hash))
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return writeError(w, http.StatusNotFound, "not_found", err.Error())
			}
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/nodes/{hash}", func(w http.ResponseWriter, r *http.Request) error {
		hash, err := requiredPathValue(r, "hash")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemanode.Point{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if req.GetHash() != "" && req.GetHash() != hash {
			return writeError(w, http.StatusBadRequest, "bad_request", "body hash conflicts with path hash")
		}
		req.SetHash(hash)
		resp, err := services.Node.Save(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("DELETE /api/v1/nodes/{hash}", func(w http.ResponseWriter, r *http.Request) error {
		hash, err := requiredPathValue(r, "hash")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Node.Remove(r.Context(), schemaapi.String(hash)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/subscriptions", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Subscribe.Get(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/subscriptions", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.SaveLinkReq{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Subscribe.Save(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("DELETE /api/v1/subscriptions", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.LinkReq{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Subscribe.Remove(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("POST /api/v1/subscriptions:update", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.LinkReq{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Subscribe.Update(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/publishes", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Subscribe.ListPublish(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/publishes/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		publish := &schemanode.Publish{}
		if err := readJSONRequestBody(r, publish); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemaapi.SavePublishRequest{}
		req.SetName(name)
		req.SetPublish(publish)
		if _, err := services.Subscribe.SavePublish(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("DELETE /api/v1/publishes/{name}", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Subscribe.RemovePublish(r.Context(), schemaapi.String(name)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("POST /api/v1/publishes/{name}/resolve", func(w http.ResponseWriter, r *http.Request) error {
		name, err := requiredPathValue(r, "name")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		var body struct {
			Path     string `json:"path"`
			Password string `json:"password"`
		}
		if err := json.UnmarshalRead(r.Body, &body); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("decode request json failed: %v", err))
		}
		req := &schemaapi.PublishRequest{}
		req.SetName(name)
		req.SetPath(body.Path)
		req.SetPassword(body.Password)
		resp, err := services.Subscribe.Publish(r.Context(), req)
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})

	register("GET /api/v1/tags", func(w http.ResponseWriter, r *http.Request) error {
		if hasPageQuery(r) {
			req, err := tagPageRequestFromQuery(r)
			if err != nil {
				return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
			}
			resp, err := services.Tag.ListPage(r.Context(), req)
			if err != nil {
				return err
			}
			return writeJSON(w, http.StatusOK, resp)
		}

		resp, err := services.Tag.List(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/tags/{tag}", func(w http.ResponseWriter, r *http.Request) error {
		tagName, err := requiredPathValue(r, "tag")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req := &schemaapi.SaveTagReq{}
		if err := readJSONBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		req.SetTag(tagName)
		if _, err := services.Tag.Save(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("DELETE /api/v1/tags/{tag}", func(w http.ResponseWriter, r *http.Request) error {
		tagName, err := requiredPathValue(r, "tag")
		if err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Tag.Remove(r.Context(), schemaapi.String(tagName)); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})

	register("GET /api/v1/connections", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Connections.Conns(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("POST /api/v1/connections:close", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaapi.NotifyRemoveConnections{}
		if err := json.UnmarshalRead(r.Body, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Connections.CloseConn(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("GET /api/v1/connections/total", TrafficTotals(traffic))
	register("GET /api/v1/connections/events", TrafficEvents(traffic))
	register("GET /api/v1/connections/failed-history", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Connections.FailedHistory(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})
	register("GET /api/v1/connections/history", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Connections.AllHistory(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSON(w, http.StatusOK, resp)
	})

	register("GET /api/v1/tools/interfaces", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Tools.GetInterface(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("GET /api/v1/tools/licenses", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Tools.Licenses(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("GET /api/v1/tools/logs", func(w http.ResponseWriter, r *http.Request) error {
		stream, err := newSSEStream(r.Context(), w, "log")
		if err != nil {
			return writeError(w, http.StatusInternalServerError, "stream_unsupported", err.Error())
		}
		err = services.Tools.Log(&schemaapi.Empty{}, &toolsLogStream{sseStream: stream})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	})
	register("GET /api/v1/tools/logs/v2", func(w http.ResponseWriter, r *http.Request) error {
		stream, err := newSSEStream(r.Context(), w, "logv2")
		if err != nil {
			return writeError(w, http.StatusInternalServerError, "stream_unsupported", err.Error())
		}
		err = services.Tools.Logv2(&schemaapi.Empty{}, &toolsLogV2Stream{sseStream: stream})
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	})

	register("GET /api/v1/backup/config", func(w http.ResponseWriter, r *http.Request) error {
		resp, err := services.Backup.Get(r.Context(), &schemaapi.Empty{})
		if err != nil {
			return err
		}
		return writeJSONResponse(w, http.StatusOK, resp)
	})
	register("PUT /api/v1/backup/config", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemaconfig.BackupOption{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Backup.Save(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("POST /api/v1/backup:run", func(w http.ResponseWriter, r *http.Request) error {
		if _, err := services.Backup.Backup(r.Context(), &schemaapi.Empty{}); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
	register("POST /api/v1/backup:restore", func(w http.ResponseWriter, r *http.Request) error {
		req := &schemabackup.RestoreOption{}
		if err := readJSONRequestBody(r, req); err != nil {
			return writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		}
		if _, err := services.Backup.Restore(r.Context(), req); err != nil {
			return err
		}
		return writeJSON(w, http.StatusNoContent, nil)
	})
}

func hasPageQuery(r *http.Request) bool {
	q := r.URL.Query()
	return q.Has("page") || q.Has("page_size") || q.Has("query")
}

func pageRequestFromQuery(r *http.Request) (*schemaapi.PageRequest, error) {
	var err error
	page := uint32(0)
	pageSize := uint32(0)

	if qv := r.URL.Query().Get("page"); qv != "" {
		page, err = parseUint32(qv)
		if err != nil {
			return nil, fmt.Errorf("invalid query page: %w", err)
		}
	}

	if qv := r.URL.Query().Get("page_size"); qv != "" {
		pageSize, err = parseUint32(qv)
		if err != nil {
			return nil, fmt.Errorf("invalid query page_size: %w", err)
		}
	}

	req := &schemaapi.PageRequest{}
	req.SetPage(page)
	req.SetPageSize(pageSize)
	req.SetQuery(r.URL.Query().Get("query"))
	return req, nil
}

func tagPageRequestFromQuery(r *http.Request) (*schemaapi.TagPageRequest, error) {
	var err error
	page := uint32(0)
	pageSize := uint32(0)

	if qv := r.URL.Query().Get("page"); qv != "" {
		page, err = parseUint32(qv)
		if err != nil {
			return nil, fmt.Errorf("invalid query page: %w", err)
		}
	}

	if qv := r.URL.Query().Get("page_size"); qv != "" {
		pageSize, err = parseUint32(qv)
		if err != nil {
			return nil, fmt.Errorf("invalid query page_size: %w", err)
		}
	}

	req := &schemaapi.TagPageRequest{}
	req.SetPage(page)
	req.SetPageSize(pageSize)
	req.SetQuery(r.URL.Query().Get("query"))
	return req, nil
}

func parseUint32(v string) (uint32, error) {
	u, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(u), nil
}

func requiredPathValue(r *http.Request, key string) (string, error) {
	value := r.PathValue(key)
	if value == "" {
		return "", fmt.Errorf("path parameter %q is required", key)
	}
	return value, nil
}

func ruleIndexFromPath(r *http.Request) (*schemaapi.RuleIndex, error) {
	name, err := requiredPathValue(r, "name")
	if err != nil {
		return nil, err
	}
	indexRaw, err := requiredPathValue(r, "index")
	if err != nil {
		return nil, err
	}
	index, err := parseUint32(indexRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid rule index: %w", err)
	}
	req := &schemaapi.RuleIndex{}
	req.SetName(name)
	req.SetIndex(index)
	return req, nil
}

type sseStream struct {
	ctx     context.Context
	w       http.ResponseWriter
	flusher http.Flusher
	event   string
}

func newSSEStream(ctx context.Context, w http.ResponseWriter, event string) (*sseStream, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("http streaming is not supported")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	return &sseStream{
		ctx:     ctx,
		w:       w,
		flusher: flusher,
		event:   event,
	}, nil
}

func (s *sseStream) sendJSON(m any) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.w, "event: %s\n", s.event); err != nil {
		return err
	}
	if _, err := s.w.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := s.w.Write(data); err != nil {
		return err
	}
	if _, err := s.w.Write([]byte("\n\n")); err != nil {
		return err
	}
	s.flusher.Flush()
	return nil
}

func (s *sseStream) Context() context.Context { return s.ctx }

type toolsLogStream struct {
	*sseStream
}

func (s *toolsLogStream) Send(m *schematools.Log) error { return s.sendJSON(m) }

type toolsLogV2Stream struct {
	*sseStream
}

func (s *toolsLogV2Stream) Send(m *schematools.Logv2) error { return s.sendJSON(m) }
