package netapi

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

type mappedPolicyError struct{ error }

func (e mappedPolicyError) Unwrap() error { return e.error }
func (mappedPolicyError) As(target any) bool {
	if value, ok := target.(**net.OpError); ok {
		*value = &net.OpError{Op: "block", Err: errors.New("policy")}
		return true
	}
	return false
}
func TestPolicyBlockSurvivesTransportWrappingAndJoining(t *testing.T) {
	block := &net.OpError{Op: "block", Err: errors.New("policy")}
	dial := &net.OpError{Op: "dial", Err: errors.New("transport failure")}
	var absent *net.OpError
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"none", nil, false}, {"typed_nil", absent, false}, {"direct", block, true},
		{"wrapped", fmt.Errorf("request: %w", block), true},
		{"transport_wrapped", &net.OpError{Op: "dial", Err: block}, true},
		{"later_join_branch", errors.Join(dial, fmt.Errorf("nested: %w", block)), true},
		{"custom_mapping", mappedPolicyError{error: dial}, true},
		{"real_dial", dial, false}, {"message_only", errors.New("block: policy denied"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsBlockError(tc.err); got != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
}
