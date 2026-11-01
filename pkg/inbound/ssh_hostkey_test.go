package inbound

import (
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	gossh "golang.org/x/crypto/ssh"
)

func TestSSHHostKeyGenerationAndStability(t *testing.T) {
	config := new(contract.SSHProtocol)
	if err := fillContractSSHHostKey(config); err != nil {
		t.Fatal(err)
	}
	if config.HostKey == "" {
		t.Fatal("host key was not generated")
	}
	key, err := gossh.ParsePrivateKey([]byte(config.HostKey))
	if err != nil {
		t.Fatal(err)
	}
	if key.PublicKey().Type() != gossh.KeyAlgoED25519 {
		t.Fatalf("unexpected key algorithm: %s", key.PublicKey().Type())
	}
	first := config.HostKey
	if err := fillContractSSHHostKey(config); err != nil {
		t.Fatal(err)
	}
	if config.HostKey != first {
		t.Fatal("saving regenerated the SSH host key")
	}
	other := new(contract.SSHProtocol)
	if err := fillContractSSHHostKey(other); err != nil {
		t.Fatal(err)
	}
	if other.HostKey == first {
		t.Fatal("separate SSH inbounds share their host key")
	}
}

func TestFillGeneratedContractFieldsSSH(t *testing.T) {
	inbound := contract.Inbound{Protocol: contract.Protocol{Type: contract.ProtocolSSH, SSH: &contract.SSHProtocol{}}}
	if err := fillGeneratedContractFields(&inbound); err != nil {
		t.Fatal(err)
	}
	if inbound.Protocol.SSH.HostKey == "" {
		t.Fatal("SSH key was not persisted in protocol config")
	}
}
