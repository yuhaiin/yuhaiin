package anyconnect

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// The authentication exchange is a short series of XML documents POSTed over the
// HTTPS connection. The client opens with type="init"; the server replies with
// type="auth-request" carrying a form; the client answers with type="auth-reply"
// filling that form's inputs; and the server ends with type="complete" and a
// session cookie. Servers vary in how many rounds they take — ocserv asks for
// the username and password in one form or two depending on its auth backend —
// so the client loops on whatever form it is handed rather than assuming a fixed
// number of steps.

// clientVersion is the AnyConnect client version veepin reports. Servers gate
// behaviour on it, and this is the version the protocol draft uses in its
// examples.
const clientVersion = "v5.01"

// configAuth is the root element of every message in the exchange, in both
// directions. Fields not relevant to a given type stay zero.
type configAuth struct {
	XMLName xml.Name `xml:"config-auth"`
	Client  string   `xml:"client,attr"`
	Type    string   `xml:"type,attr"`
	Version struct {
		Who  string `xml:"who,attr"`
		Text string `xml:",chardata"`
	} `xml:"version"`
	Auth         auth   `xml:"auth"`
	SessionID    string `xml:"session-id,omitempty"`
	SessionToken string `xml:"session-token,omitempty"`
}

// auth carries the server's form (in an auth-request) or the client's answers
// (in an auth-reply). Error is the server's message when it rejects credentials.
type auth struct {
	ID string `xml:"id,attr"`
	// Form is a pointer so a message that carries no form omits the element
	// entirely. An empty <form method="" action=""/> is not equivalent: clients
	// read it as a form they are being asked to fill and reject it as malformed.
	Form  *form  `xml:"form,omitempty"`
	Error string `xml:"error,omitempty"`
	// Fields are the client's filled-in answers, rendered as <username>x</username>
	// style elements the server reads by name.
	Fields []authField `xml:",any"`
}

// authField is one answered input, whose element name is the input's name.
type authField struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// form is a server-presented credential form.
type form struct {
	Method string      `xml:"method,attr"`
	Action string      `xml:"action,attr"`
	Inputs []formInput `xml:"input"`
}

// formInput is one field the server wants filled.
type formInput struct {
	Type  string `xml:"type,attr"`
	Name  string `xml:"name,attr"`
	Label string `xml:"label,attr"`
}

// marshalConfigAuth renders a message with the XML declaration servers expect.
func marshalConfigAuth(m configAuth) ([]byte, error) {
	m.Client = "vpn"
	m.Version.Who = "vpn"
	m.Version.Text = clientVersion
	body, err := xml.MarshalIndent(m, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("anyconnect: marshal %s: %w", m.Type, err)
	}
	return append([]byte(xml.Header), body...), nil
}

func parseConfigAuth(body []byte) (configAuth, error) {
	var m configAuth
	if err := xml.Unmarshal(body, &m); err != nil {
		return configAuth{}, fmt.Errorf("anyconnect: parse auth message: %w", err)
	}
	return m, nil
}

// initMessage opens the exchange.
func initMessage() configAuth {
	return configAuth{Type: "init"}
}

// answerForm fills a server-presented form from the credentials, matching inputs
// by name. Inputs whose names are unknown are answered empty rather than
// omitted, since a server that asked for a field expects to see it.
func answerForm(f *form, username, password string) configAuth {
	m := configAuth{Type: "auth-reply"}
	for _, in := range f.Inputs {
		var value string
		switch {
		case isUsernameField(in):
			value = username
		case isPasswordField(in):
			value = password
		}
		m.Auth.Fields = append(m.Auth.Fields, authField{
			XMLName: xml.Name{Local: in.Name},
			Value:   value,
		})
	}
	return m
}

// isUsernameField and isPasswordField classify a form input. Servers name these
// inconsistently ("username", "user", "uname", "secondary_username"), so the
// input's declared type is trusted first and its name only as a fallback.
func isUsernameField(in formInput) bool {
	return strings.Contains(strings.ToLower(in.Name), "user") ||
		strings.Contains(strings.ToLower(in.Name), "uname")
}

func isPasswordField(in formInput) bool {
	return in.Type == "password" ||
		strings.Contains(strings.ToLower(in.Name), "pass") ||
		strings.Contains(strings.ToLower(in.Name), "secret")
}

// credentialForm is the form a veepin server presents: one username and one
// password, answered in a single round.
func credentialForm() configAuth {
	return configAuth{
		Type: "auth-request",
		Auth: auth{
			ID: "main",
			Form: &form{
				Method: "post",
				Action: authPath,
				Inputs: []formInput{
					{Type: "text", Name: "username", Label: "Username:"},
					{Type: "password", Name: "password", Label: "Password:"},
				},
			},
		},
	}
}

// completeMessage ends a successful exchange, handing the client the session
// token it presents on the CONNECT request.
func completeMessage(sessionID, token string) configAuth {
	m := configAuth{Type: "complete", SessionID: sessionID, SessionToken: token}
	m.Auth.ID = "success"
	return m
}

// failureMessage rejects the credentials by re-presenting the form with an
// error attached, which is how the protocol reports a bad password: a client is
// expected to be able to try again.
func failureMessage(reason string) configAuth {
	m := credentialForm()
	m.Auth.Error = reason
	return m
}

// field returns the value the client supplied for an input name.
func (a auth) field(name string) string {
	for _, f := range a.Fields {
		if strings.EqualFold(f.XMLName.Local, name) {
			return f.Value
		}
	}
	return ""
}
