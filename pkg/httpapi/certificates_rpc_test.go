package httpapi

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"uuid"

	manager "github.com/Asutorufa/yuhaiin/pkg/cert/manager"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/management/permission"
	"github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

func TestCertificateRPCPersistsAndNeverReturnsCredentials(t *testing.T) {
	db, err := sqlite.Open(t.Context(), filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner, err := manager.New(manager.Options{Store: certificates.New(db.DB()), Issue: func(context.Context, contract.Config) (certificates.Material, error) {
		return certificates.Material{}, errors.New("not scheduled")
	}})
	if err != nil {
		t.Fatal(err)
	}
	handlers := newV2Handlers(V2Services{Certificates: owner})
	call := func(endpoint v2Endpoint, body any) *httptest.ResponseRecorder {
		t.Helper()
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/"+string(endpoint), bytes.NewReader(data))
		w := httptest.NewRecorder()
		if err := handlers.values[endpoint](w, r); err != nil {
			t.Fatal(err)
		}
		return w
	}
	private := "never-return-this-provider-token"
	provider := contract.DNSProvider{ID: uuid.New().String(), Name: "Example zone", Type: "cloudflare", ZoneID: strings.Repeat("a", 32), ZoneName: "example.com"}
	w := call(v2CertificateProviderSave, contract.ProviderWrite{Provider: provider, Token: private})
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), private) {
		t.Fatal("credential save projection", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &provider); err != nil {
		t.Fatal(err)
	}
	cfg := contract.Config{ID: uuid.New().String(), Name: "Site", Domains: []string{"site.example.com"}, DirectoryURL: contract.LetsEncryptStaging, Email: "ops@example.com", TermsAccepted: true, AutoRenew: true, Challenge: contract.Challenge{Type: "dns-01", DNSProviderID: provider.ID}}
	w = call(v2CertificateSave, contract.SaveRequest{Certificate: cfg})
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var resource contract.Resource
	if err := json.Unmarshal(w.Body.Bytes(), &resource); err != nil {
		t.Fatal(err)
	}
	w = call(v2CertificatesList, emptyRequest{})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "site.example.com") || strings.Contains(w.Body.String(), private) {
		t.Fatal("certificate list lost config or exposed secret", w.Code)
	}
	if w := call(v2CertificateProviderDelete, contract.RevisionRequest{ID: provider.ID, Revision: provider.Revision}); w.Code != http.StatusConflict {
		t.Fatal("referenced provider deleted", w.Code)
	}
	if w := call(v2CertificateSave, contract.SaveRequest{Certificate: cfg}); w.Code != http.StatusConflict {
		t.Fatal("stale certificate update accepted", w.Code)
	}
	if w := call(v2CertificateDelete, contract.RevisionRequest{ID: cfg.ID, Revision: resource.Revision}); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	if w := call(v2CertificateProviderDelete, contract.RevisionRequest{ID: provider.ID, Revision: provider.Revision}); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	if w := call(v2CertificateProviderSave, contract.ProviderWrite{Provider: provider, Token: strings.Repeat("x", 9<<10)}); w.Code != http.StatusBadRequest {
		t.Fatal("oversized secret input accepted", w.Code)
	}
	for _, endpoint := range []v2Endpoint{v2CertificateSave, v2CertificateDelete, v2CertificateRenew, v2CertificateProviderSave, v2CertificateProviderDelete} {
		if v2Permissions[endpoint] != permission.CertificatesManage {
			t.Fatal("certificate mutation lacks manage scope", endpoint)
		}
	}
	if v2Permissions[v2CertificatesList] != permission.CertificatesRead {
		t.Fatal("certificate read lacks read scope")
	}
}
