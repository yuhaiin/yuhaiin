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

type listConfigRuntimeStub struct {
	store *plainstore.RouteSettingsStore
}

func (s listConfigRuntimeStub) SaveConfig(ctx context.Context, config contractroute.ListConfig, interval uint64) error {
	return s.store.SaveListSettings(ctx, plainstore.RouteListSettings{
		RefreshInterval: interval, LastRefreshTime: 999,
		MaxMindDBDownloadURL: config.MaxMindDBGeoIP.DownloadURL,
	})
}
func (listConfigRuntimeStub) Refresh(context.Context) error      { return nil }
func (listConfigRuntimeStub) ApplyChanges(context.Context) error { return nil }
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
	body := `{"refreshInterval":"60","lastRefreshTime":"0","error":"NOT DOWNLOAD","maxMindDbGeoIp":{"downloadUrl":"https://example.com/geo.mmdb","error":"NOT DOWNLOAD"}}`
	req := httptest.NewRequest(http.MethodPut, "/api/v2/route/lists/config", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"lastRefreshTime":"999"`) || strings.Contains(recorder.Body.String(), "NOT DOWNLOAD") {
		t.Fatalf("response contains stale runtime state: %s", recorder.Body.String())
	}
	got, err := settings.ListSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRefreshTime != 999 || got.Error != "" || got.MaxMindDBError != "" {
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

	post := httptest.NewRequest(http.MethodPost, "/api/v2/inbounds", strings.NewReader(string(body)))
	postRecorder := httptest.NewRecorder()
	mux.ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusCreated {
		t.Fatalf("POST status = %d body = %s", postRecorder.Code, postRecorder.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v2/inbounds/reversehttp", nil)
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

	list := httptest.NewRequest(http.MethodGet, "/api/v2/inbounds?page=1&page_size=10&query=reverse", nil)
	listRecorder := httptest.NewRecorder()
	mux.ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("LIST status = %d body = %s", listRecorder.Code, listRecorder.Body.String())
	}
	if !strings.Contains(listRecorder.Body.String(), `"items"`) || strings.Contains(listRecorder.Body.String(), `"names"`) {
		t.Fatalf("LIST body is not v2 list shape: %s", listRecorder.Body.String())
	}
}
