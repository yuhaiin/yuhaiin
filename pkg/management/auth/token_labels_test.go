package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestTokenLabelsPersistAcrossListRotateAndUpdate(t *testing.T) {
	s := testStore(t)
	admin := testUser(t, s, "admin", Admin)
	u := testUser(t, s, "reader", ReadOnly)
	other := testUser(t, s, "other", ReadOnly)

	issued, err := s.IssueLabeledToken(t.Context(), principal(u), u.ID, []Permission{NodesRead}, 0, TokenLabels{Name: "  CI deploy  ", Note: "used by\nGitHub Actions"})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Name != "CI deploy" || issued.Note != "used by\nGitHub Actions" {
		t.Fatalf("issued labels = %q/%q", issued.Name, issued.Note)
	}
	listed, err := s.Credentials(t.Context(), u.ID)
	if err != nil || len(listed) != 1 || listed[0].Name != "CI deploy" || listed[0].Note != issued.Note {
		t.Fatalf("listed = %+v, %v", listed, err)
	}

	rotated, err := s.RotateToken(t.Context(), principal(u), issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Name != "CI deploy" || rotated.Note != issued.Note {
		t.Fatalf("rotation dropped labels: %+v", rotated.Credential)
	}

	if _, err := s.UpdateTokenLabels(t.Context(), principal(other), rotated.ID, TokenLabels{Name: "stolen"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign update: %v", err)
	}
	updated, err := s.UpdateTokenLabels(t.Context(), principal(admin), rotated.ID, TokenLabels{Name: "renamed"})
	if err != nil || updated.Name != "renamed" || updated.Note != "" || len(updated.Scopes) != 1 {
		t.Fatalf("admin update = %+v, %v", updated, err)
	}
	if _, err := s.UpdateTokenLabels(t.Context(), principal(u), issued.ID, TokenLabels{Name: "revoked"}); err == nil {
		t.Fatal("updated a revoked token")
	}
	if _, err := s.Authenticate(t.Context(), rotated.Secret, "token"); err != nil {
		t.Fatalf("label update broke authentication: %v", err)
	}
}

func TestTokenLabelsValidation(t *testing.T) {
	s := testStore(t)
	u := testUser(t, s, "reader", ReadOnly)
	for _, labels := range []TokenLabels{
		{Name: strings.Repeat("あ", maxTokenNameLength+1)},
		{Note: strings.Repeat("x", maxTokenNoteLength+1)},
		{Name: "line\nbreak"},
		{Note: "bell\a"},
		{Name: "\xff"},
	} {
		if _, err := s.IssueLabeledToken(t.Context(), principal(u), u.ID, []Permission{NodesRead}, 0, labels); !errors.Is(err, ErrInvalid) {
			t.Fatalf("labels %q accepted: %v", labels, err)
		}
	}
	if _, err := s.IssueLabeledToken(t.Context(), principal(u), u.ID, []Permission{NodesRead}, 0, TokenLabels{Name: strings.Repeat("あ", maxTokenNameLength)}); err != nil {
		t.Fatalf("max-length multibyte name rejected: %v", err)
	}
}
