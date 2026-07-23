package socks4a

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/auth"
)

type usernameAuthStub struct{}

func (usernameAuthStub) AuthUsername(username string) (auth.Principal, error) {
	if username == "alice" {
		return auth.Principal{UserID: "user-1"}, nil
	}
	return auth.Principal{}, errors.New("invalid username")
}

func TestHandshakeUsesCentralUsernameAuthenticator(t *testing.T) {
	for _, tt := range []struct {
		name    string
		user    string
		wantErr bool
	}{
		{name: "valid", user: "alice"},
		{name: "invalid", user: "wrong", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, serverConn := net.Pipe()
			defer client.Close()
			defer serverConn.Close()
			clientResult := make(chan error, 1)
			go func() {
				defer close(clientResult)
				request := []byte{4, CommandConnect, 0, 80, 0, 0, 0, 1}
				request = append(request, tt.user...)
				request = append(request, 0)
				if _, err := client.Write(request); err != nil {
					clientResult <- err
					return
				}
				if tt.wantErr {
					clientResult <- nil
					return
				}
				if _, err := client.Write([]byte("example.com\x00")); err != nil {
					clientResult <- err
					return
				}
				var response [8]byte
				if _, err := io.ReadFull(client, response[:]); err != nil {
					clientResult <- err
					return
				}
				if response[1] != 90 {
					clientResult <- errors.New("SOCKS4A request was rejected")
					return
				}
				clientResult <- nil
			}()

			srv := &Server{authenticator: usernameAuthStub{}}
			_, err := srv.Handshake(serverConn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Handshake() error = %v, wantErr=%v", err, tt.wantErr)
			}
			if clientErr := <-clientResult; clientErr != nil {
				t.Fatal(clientErr)
			}
		})
	}
}
