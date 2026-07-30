package socks5

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
)

type basicAuthenticatorStub struct {
	username string
	password string
}

func (a basicAuthenticatorStub) AuthBasic(username, password string) (auth.Principal, error) {
	if username != a.username || password != a.password {
		return auth.Principal{}, errors.New("invalid credential")
	}
	return auth.Principal{UserID: "test-user"}, nil
}

func TestHandshake1UsesCentralBasicAuthenticator(t *testing.T) {
	for _, tt := range []struct {
		name    string
		user    string
		pass    string
		wantErr bool
	}{
		{name: "valid", user: "alice", pass: "secret"},
		{name: "invalid", user: "alice", pass: "wrong", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			clientResult := make(chan error, 1)
			go func() {
				defer close(clientResult)
				if _, err := client.Write([]byte{5, 1, tools.UserAndPassword}); err != nil {
					clientResult <- err
					return
				}
				var response [2]byte
				if _, err := io.ReadFull(client, response[:]); err != nil {
					clientResult <- err
					return
				}
				if response[0] != 5 || response[1] != tools.UserAndPassword {
					clientResult <- errors.New("server selected unexpected auth method")
					return
				}
				request := []byte{1, byte(len(tt.user))}
				request = append(request, tt.user...)
				request = append(request, byte(len(tt.pass)))
				request = append(request, tt.pass...)
				if _, err := client.Write(request); err != nil {
					clientResult <- err
					return
				}
				if _, err := io.ReadFull(client, response[:]); err != nil {
					clientResult <- err
					return
				}
				if (response[1] == 0) == !tt.wantErr {
					clientResult <- nil
				} else {
					clientResult <- errors.New("unexpected username/password result")
				}
			}()

			s := &Server{authenticator: basicAuthenticatorStub{username: "alice", password: "secret"}}
			err := s.handshake1(server, make([]byte, 1024))
			if (err != nil) != tt.wantErr {
				t.Fatalf("handshake1() error = %v, wantErr=%v", err, tt.wantErr)
			}
			if clientErr := <-clientResult; clientErr != nil {
				t.Fatal(clientErr)
			}
		})
	}
}

func TestHandshake1RejectsNoAuthWhenCentralAuthenticatorExists(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	clientResult := make(chan error, 1)
	go func() {
		defer close(clientResult)
		if _, err := client.Write([]byte{5, 1, tools.NoAuthenticationRequired}); err != nil {
			clientResult <- err
			return
		}
		var response [2]byte
		if _, err := io.ReadFull(client, response[:]); err != nil {
			clientResult <- err
			return
		}
		if response != [2]byte{5, tools.NoAcceptableMethods} {
			clientResult <- errors.New("unexpected no-auth response")
		}
	}()

	s := &Server{authenticator: basicAuthenticatorStub{username: "alice", password: "secret"}}
	if err := s.handshake1(server, make([]byte, 1024)); err == nil {
		t.Fatal("no-auth method was accepted with central authenticator")
	}
	if err := <-clientResult; err != nil {
		t.Fatal(err)
	}
}
