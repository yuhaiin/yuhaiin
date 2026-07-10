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
