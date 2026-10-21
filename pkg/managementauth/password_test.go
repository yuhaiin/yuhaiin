package managementauth

import (
	"bufio"
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/text/unicode/norm"
)

type cryptoClient struct {
	input  io.WriteCloser
	output *bufio.Scanner
}

func nodeClient(t *testing.T) *cryptoClient {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node.js required for Web Crypto interoperability tests")
	}
	cmd := exec.CommandContext(t.Context(), "node", filepath.Join("..", "..", "example", "management-auth", "bridge.mjs"))
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = in.Close()
		if err := cmd.Wait(); err != nil && !errors.Is(err, io.EOF) {
			t.Logf("client exit: %v %s", err, stderr.String())
		}
	})
	return &cryptoClient{in, bufio.NewScanner(out)}
}

func (c *cryptoClient) call(t *testing.T, request any, out any) {
	t.Helper()
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.input.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	if !c.output.Scan() {
		t.Fatalf("client response missing: %v", c.output.Err())
	}
	if err := json.Unmarshal(c.output.Bytes(), out); err != nil {
		t.Fatalf("client response error: %v", err)
	}
}

func clientCredential(t *testing.T, password string, params PasswordParameters) string {
	t.Helper()
	salt, err := base64.RawURLEncoding.DecodeString(params.Salt)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := pbkdf2.Key(sha256.New, norm.NFC.String(password), salt, params.Iterations, params.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(derived)
}

func TestWebCryptoEncodingNormalizationAndSalt(t *testing.T) {
	c := nodeClient(t)
	p := parameters(clientSalt())
	for _, password := range []string{"correct horse battery staple", "密码-é-🦊", "密码-e\u0301-🦊", "  do not trim  "} {
		var got string
		c.call(t, map[string]any{"operation": "derive", "password": password, "parameters": p}, &got)
		if got != clientCredential(t, password, p) {
			t.Fatal("Web Crypto and Go PBKDF2 disagree")
		}
	}
	s := testStore(t)
	first, _, err := s.CreateUser(t.Context(), "local", "first", Admin, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = s.CreateUser(t.Context(), first.ID, "second", ReadOnly, false)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewPasswordService(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	firstParams, err := service.Parameters(t.Context(), "first")
	if err != nil {
		t.Fatal(err)
	}
	secondParams, err := service.Parameters(t.Context(), "second")
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := service.Parameters(t.Context(), "unknown")
	if err != nil {
		t.Fatal(err)
	}
	again, err := service.Parameters(t.Context(), "UNKNOWN")
	if err != nil {
		t.Fatal(err)
	}
	if firstParams.Salt == secondParams.Salt || unknown != again || len(unknown.Salt) != len(firstParams.Salt) {
		t.Fatal("salt uniqueness/unknown-account response failed")
	}
}

func TestEnrollmentLoginChangeAndSessionRevocation(t *testing.T) {
	s := testStore(t)
	u, enrollment, err := s.CreateUser(t.Context(), "local", "admin", Admin, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPasswordService(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	params, err := p.EnrollmentParameters(t.Context(), enrollment.Secret)
	if err != nil {
		t.Fatal(err)
	}
	credential := clientCredential(t, "initial password", params)
	if err := p.Enroll(t.Context(), enrollment.Secret, credential); err != nil {
		t.Fatal(err)
	}
	if err := p.Enroll(t.Context(), enrollment.Secret, credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("enrollment reused: %v", err)
	}
	var verifier, salt []byte
	if err := s.db.QueryRowContext(t.Context(), `SELECT credential,server_salt FROM management_users WHERE id=?`, u.ID).Scan(&verifier, &salt); err != nil {
		t.Fatal(err)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(credential)
	if bytes.Equal(verifier, decoded) || base64.RawURLEncoding.EncodeToString(salt) == params.Salt {
		t.Fatal("client credential or salt reused at rest")
	}
	for _, login := range []string{"admin", "missing"} {
		if _, err := p.Login(t.Context(), login, clientCredential(t, "wrong password", params)); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("bad login %s: %v", login, err)
		}
	}
	session, err := p.Login(t.Context(), "ADMIN", credential)
	if err != nil {
		t.Fatal(err)
	}
	if session.ExpiresAt-session.CreatedAt != int64((8 * time.Hour).Seconds()) {
		t.Fatal("session expiry contract")
	}
	if _, err := s.Authenticate(t.Context(), session.Secret, "token"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("session accepted as API token")
	}
	if _, err := s.Authenticate(t.Context(), session.Secret, "session"); err != nil {
		t.Fatal(err)
	}
	if err := s.logout(t.Context(), session.Secret); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(t.Context(), session.Secret, "session"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("logout did not revoke session")
	}
	reset, err := s.ResetEnrollment(t.Context(), u.ID, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := p.EnrollmentParameters(t.Context(), reset.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Salt == params.Salt {
		t.Fatal("password change reused client salt")
	}
	if err := p.Enroll(t.Context(), reset.Secret, clientCredential(t, "changed password", changed)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Login(t.Context(), u.Login, credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("old credential survived change")
	}
	if _, err := p.Login(t.Context(), u.Login, clientCredential(t, "changed password", changed)); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserReferenceNeverTransmitsPassword(t *testing.T) {
	s := testStore(t)
	_, capability, err := s.CreateUser(t.Context(), "local", "admin", Admin, true)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPasswordService(t.Context(), s)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Store: s, Passwords: p}
	mux := http.NewServeMux()
	server.Register(mux)
	gate := server.Wrap(mux)
	const password = "private raw password never sent"
	var leaked atomic.Bool
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if bytes.Contains(body, []byte(password)) || strings.Contains(r.URL.String(), capability.Secret) {
			leaked.Store(true)
		}
		gate.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	c := nodeClient(t)
	var enrolled bool
	c.call(t, map[string]any{"operation": "enroll", "origin": httpServer.URL, "capability": capability.Secret, "password": password}, &enrolled)
	if !enrolled {
		t.Fatal("browser enrollment failed")
	}
	var session IssuedCredential
	c.call(t, map[string]any{"operation": "login", "origin": httpServer.URL, "name": "admin", "password": password}, &session)
	if session.Secret == "" || leaked.Load() {
		t.Fatal("browser login failed or raw password leaked on wire")
	}
}
