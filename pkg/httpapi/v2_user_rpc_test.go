package httpapi

import (
	"context"
	json "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
	contractuser "github.com/Asutorufa/yuhaiin/pkg/contract/user"
	storagesqlite "github.com/Asutorufa/yuhaiin/pkg/storage/sqlite"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

func TestV2UserCRUDAndBlankPasswordPreservation(t *testing.T) {
	ctx := context.Background()
	sqliteStore, err := storagesqlite.Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqliteStore.Close()
	users := plainstore.NewUserStore(sqliteStore.DB())
	center, err := auth.NewCenter(users)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if err := handler(w, r); err != nil {
				t.Fatal(err)
			}
		})
	}, V2Services{Users: users, Auth: center})

	post := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/users.post", strings.NewReader(`{"name":"Alice","enabled":true,"usage":"both","credential":{"type":"basic","basic":{"username":"alice","password":"first-secret"}}}`))
	postRecorder := httptest.NewRecorder()
	mux.ServeHTTP(postRecorder, post)
	if postRecorder.Code != http.StatusOK || strings.Contains(postRecorder.Body.String(), "first-secret") || strings.Contains(postRecorder.Body.String(), "password") {
		t.Fatalf("POST status/body = %d/%s", postRecorder.Code, postRecorder.Body.String())
	}
	var created contractuser.UserView
	if err := json.Unmarshal(postRecorder.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || !created.Credential.HasSecret || created.Credential.Username != "alice" {
		t.Fatalf("created user = %+v", created)
	}
	if _, err := center.AuthBasic("alice", "first-secret"); err != nil {
		t.Fatalf("new user was not reloaded: %v", err)
	}

	list := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/users.get", strings.NewReader(`{"page":1,"page_size":10,"query":"alice"}`))
	listRecorder := httptest.NewRecorder()
	mux.ServeHTTP(listRecorder, list)
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), created.ID) || strings.Contains(listRecorder.Body.String(), "first-secret") {
		t.Fatalf("LIST status/body = %d/%s", listRecorder.Code, listRecorder.Body.String())
	}

	put := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/user.put", strings.NewReader(`{"id":"`+created.ID+`","name":"Alice renamed","enabled":true,"usage":"both"}`))
	putRecorder := httptest.NewRecorder()
	mux.ServeHTTP(putRecorder, put)
	if putRecorder.Code != http.StatusOK || strings.Contains(putRecorder.Body.String(), "first-secret") {
		t.Fatalf("PUT status/body = %d/%s", putRecorder.Code, putRecorder.Body.String())
	}
	stored, err := users.Get(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Name != "Alice renamed" || stored.Credential.Basic == nil || stored.Credential.Basic.Password == nil || *stored.Credential.Basic.Password != "first-secret" {
		t.Fatalf("blank-password update did not preserve credential: %+v", stored)
	}

	deleteRequest := httptest.NewRequest(http.MethodPost, "/api/v2/rpc/user.delete", strings.NewReader(`{"id":"`+created.ID+`"}`))
	deleteRecorder := httptest.NewRecorder()
	mux.ServeHTTP(deleteRecorder, deleteRequest)
	if deleteRecorder.Code != http.StatusOK || deleteRecorder.Body.String() != "{}" {
		t.Fatalf("DELETE status/body = %d/%s", deleteRecorder.Code, deleteRecorder.Body.String())
	}
	if _, err := center.AuthBasic("alice", "first-secret"); err == nil {
		t.Fatal("deleted user still authenticates")
	}
}
