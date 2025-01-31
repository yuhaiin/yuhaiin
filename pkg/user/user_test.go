package user

import "testing"

func TestUser(t *testing.T) {
	u := &User{
		Username: "uuu",
		Password: "ppp",
	}

	t.Log(u.OnePassword())
}
