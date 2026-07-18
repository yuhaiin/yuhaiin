package httpapi

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	contractinbound "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestRegisterV2PatternsAreServeMuxCompatible(t *testing.T) {
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			_ = handler(w, r)
		})
	}, V2Services{})
}

func TestV2RouteTableHasExactlyOneHandlerPerPattern(t *testing.T) {
	handlers := newV2Handlers(V2Services{})
	seen := make(map[string]struct{}, len(v2Routes))
	for _, route := range v2Routes {
		if _, exists := seen[route.pattern]; exists {
			t.Fatalf("duplicate route pattern %q", route.pattern)
		}
		seen[route.pattern] = struct{}{}
		if _, ok := handlers.values[route.endpoint]; !ok {
			t.Fatalf("route %q has no handler for endpoint %q", route.pattern, route.endpoint)
		}
	}
	if len(handlers.values) != len(v2Routes) {
		t.Fatalf("handlers=%d routes=%d: handler registration and route table diverged", len(handlers.values), len(v2Routes))
	}
}

func TestV2RoutePatternsUsePostRPCExceptStreams(t *testing.T) {
	for _, route := range v2Routes {
		pattern := v2RoutePattern(route)
		if isV2StreamEndpoint(route.endpoint) {
			if pattern != route.pattern {
				t.Fatalf("stream route %q changed from %q to %q", route.endpoint, route.pattern, pattern)
			}
			continue
		}
		expected := "POST /api/v2/rpc/" + string(route.endpoint)
		if pattern != expected {
			t.Fatalf("route %q pattern=%q want=%q", route.endpoint, pattern, expected)
		}
	}
}

type listConfigRuntimeStub struct {
	store *plainstore.RouteSettingsStore
}

type routeRuntimeStub struct {
	applyAt int64
	applied *int
}

func (routeRuntimeStub) SaveConfig(context.Context, contractroute.Config) error { return nil }
func (routeRuntimeStub) ScheduleApply()                                         {}
func (s routeRuntimeStub) Apply(context.Context) error {
	*s.applied++
	return nil
}
func (s routeRuntimeStub) ActivationStatus(context.Context) (contractroute.RuleActivationStatus, error) {
	return contractroute.RuleActivationStatus{ApplyAt: s.applyAt}, nil
}
func (routeRuntimeStub) Test(context.Context, string) (contractroute.RuleTestResponse, error) {
	return contractroute.RuleTestResponse{}, nil
}
func (routeRuntimeStub) BlockHistory(context.Context) (contractroute.BlockHistoryList, error) {
	return contractroute.BlockHistoryList{}, nil
}

type activationListRuntimeStub struct {
	listConfigRuntimeStub
	refreshAt int64
	applied   *int
}

func (s activationListRuntimeStub) Apply(context.Context) error {
	*s.applied++
	return nil
}
func (s activationListRuntimeStub) ActivationStatus(context.Context) (contractroute.ListActivationStatus, error) {
	return contractroute.ListActivationStatus{HostIndexRefreshAt: s.refreshAt}, nil
}

func TestV2RouteActivationIsCombined(t *testing.T) {
	listApplied, ruleApplied := 0, 0
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if err := handler(w, r); err != nil {
				t.Fatal(err)
			}
		})
	}, V2Services{
		Lists: activationListRuntimeStub{refreshAt: 123, applied: &listApplied},
		Rules: routeRuntimeStub{applyAt: 456, applied: &ruleApplied},
	})

	statusRecorder := httptest.NewRecorder()
	mux.ServeHTTP(statusRecorder, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/route.activation", strings.NewReader(`{}`)))
	if statusRecorder.Code != http.StatusOK || !strings.Contains(statusRecorder.Body.String(), `"hostIndexRefreshAt":123`) || !strings.Contains(statusRecorder.Body.String(), `"ruleApplyAt":456`) {
		t.Fatalf("unexpected activation status: code=%d body=%s", statusRecorder.Code, statusRecorder.Body.String())
	}

	applyRecorder := httptest.NewRecorder()
	mux.ServeHTTP(applyRecorder, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/route.apply", strings.NewReader(`{}`)))
	if applyRecorder.Code != http.StatusOK || applyRecorder.Body.String() != "{}" || listApplied != 1 || ruleApplied != 1 {
		t.Fatalf("combined apply failed: code=%d list=%d rule=%d", applyRecorder.Code, listApplied, ruleApplied)
	}
}

func (s listConfigRuntimeStub) SaveConfig(ctx context.Context, config contractroute.ListConfig, interval uint64) error {
	return s.store.SaveListSettings(ctx, plainstore.RouteListSettings{
		RefreshInterval: interval, LastRefreshTime: 999,
		HostIndexDisk:        config.HostIndexDisk,
		MaxMindDBDownloadURL: config.MaxMindDBGeoIP.DownloadURL,
	})
}
func (listConfigRuntimeStub) Refresh(context.Context) error      { return nil }
func (listConfigRuntimeStub) ApplyChanges(context.Context) error { return nil }
func (listConfigRuntimeStub) Apply(context.Context) error        { return nil }
func (listConfigRuntimeStub) ActivationStatus(context.Context) (contractroute.ListActivationStatus, error) {
	return contractroute.ListActivationStatus{}, nil
}

func TestV2RouteListConfigDoesNotOverwriteRuntimeState(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()
	settings := plainstore.NewRouteSettingsStore(sqliteStore.DB())
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{Lists: listConfigRuntimeStub{store: settings}, RouteSettings: settings})
	body := `{"refreshInterval":"60","lastRefreshTime":"0","error":"NOT DOWNLOAD","hostIndexDisk":true,"maxMindDbGeoIp":{"downloadUrl":"https://example.com/geo.mmdb","error":"NOT DOWNLOAD"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/route.lists.config.put", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"lastRefreshTime":"999"`) || !strings.Contains(recorder.Body.String(), `"hostIndexDisk":true`) || strings.Contains(recorder.Body.String(), "NOT DOWNLOAD") {
		t.Fatalf("response contains stale runtime state: %s", recorder.Body.String())
	}
	got, err := settings.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRefreshTime != 999 || got.Error != "" || !got.HostIndexDisk || got.MaxMindDBError != "" {
		t.Fatalf("runtime state overwritten: %+v", got)
	}
}

func TestV2InboundCRUD(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sqliteStore.Close() }()

	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if err := handler(w, r); err != nil {
				_ = writeError(w, http.StatusInternalServerError, "internal", err.Error())
			}
		})
	}, V2Services{Inbounds: plainstore.NewInboundStore(sqliteStore.DB())})

	inbound := contractinbound.Inbound{
		ID:      "reversehttp",
		Name:    "Reverse HTTP",
		Enabled: true,
		Network: contractinbound.NewTypedNetwork(contractinbound.TCPUDPNetwork{Host: ":9002", UDP: contractinbound.UDPTCPOnly}),
		Transports: []contractinbound.Transport{
			contractinbound.NewTypedTransport(contractinbound.NormalTransport{}),
		},
		Protocol: contractinbound.NewTypedProtocol(contractinbound.ReverseHTTPProtocol{URL: "http://127.0.0.1:3000"}),
	}
	body, err := json.Marshal(inbound)
	if err != nil {
		t.Fatal(err)
	}

	post := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/inbounds.post", strings.NewReader(string(body)))
	postRecorder := httptest.NewRecorder()
	mux.ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusOK {
		t.Fatalf("POST status = %d body = %s", postRecorder.Code, postRecorder.Body.String())
	}

	get := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/inbound.get", strings.NewReader(`{"id":"reversehttp"}`))
	getRecorder := httptest.NewRecorder()
	mux.ServeHTTP(getRecorder, get)
	if getRecorder.Code != http.StatusOK {
		t.Fatalf("GET status = %d body = %s", getRecorder.Code, getRecorder.Body.String())
	}
	if !strings.Contains(getRecorder.Body.String(), `"reverse_http"`) {
		t.Fatalf("GET body missing reverse_http tagged field: %s", getRecorder.Body.String())
	}
	if strings.Contains(getRecorder.Body.String(), `"config"`) {
		t.Fatalf("GET body contains config wrapper: %s", getRecorder.Body.String())
	}

	list := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/inbounds.get", strings.NewReader(`{"page":1,"page_size":10,"query":"reverse"}`))
	listRecorder := httptest.NewRecorder()
	mux.ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("LIST status = %d body = %s", listRecorder.Code, listRecorder.Body.String())
	}
	if !strings.Contains(listRecorder.Body.String(), `"items"`) || strings.Contains(listRecorder.Body.String(), `"names"`) {
		t.Fatalf("LIST body is not v2 list shape: %s", listRecorder.Body.String())
	}
}
