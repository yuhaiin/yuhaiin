package inbound

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/cert"
	contract "github.com/Asutorufa/yuhaiin/pkg/contract/inbound"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/reality"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type ContractStore struct {
	store   *plainstore.InboundStore
	runtime *Inbound
}

func NewContractStore(store *plainstore.InboundStore, runtime *Inbound) *ContractStore {
	return &ContractStore{store: store, runtime: runtime}
}

func (s *ContractStore) Sync(ctx context.Context) error {
	items, err := s.List(ctx)
	if err != nil {
		return err
	}
	for _, item := range items {
		s.runtime.SaveContract(item)
	}
	settings, err := s.Settings(ctx)
	if err != nil {
		return err
	}
	s.applySettings(settings)
	return nil
}

func (s *ContractStore) List(ctx context.Context) ([]contract.Inbound, error) {
	return s.store.List(ctx)
}

func (s *ContractStore) Get(ctx context.Context, id string) (contract.Inbound, error) {
	return s.store.Get(ctx, id)
}

func (s *ContractStore) Save(ctx context.Context, inbound contract.Inbound, updatedAt int64) error {
	if err := fillGeneratedContractFields(&inbound); err != nil {
		return err
	}
	if updatedAt == 0 {
		updatedAt = time.Now().Unix()
	}
	if err := s.store.Save(ctx, inbound, updatedAt); err != nil {
		return err
	}
	s.runtime.SaveContract(inbound)
	return nil
}

func (s *ContractStore) Delete(ctx context.Context, id string) error {
	if err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	s.runtime.Remove(id)
	return nil
}

func (s *ContractStore) Settings(ctx context.Context) (plainstore.InboundSettings, error) {
	return s.store.Settings(ctx)
}

func (s *ContractStore) SaveSettings(ctx context.Context, settings plainstore.InboundSettings) error {
	if err := s.store.SaveSettings(ctx, settings); err != nil {
		return err
	}
	s.applySettings(settings)
	return nil
}

func (s *ContractStore) applySettings(settings plainstore.InboundSettings) {
	s.runtime.SetHijackDns(settings.HijackDNS)
	s.runtime.SetHijackDnsFakeip(settings.HijackDNSFakeIP)
	s.runtime.SetSniff(settings.Sniff)
}

func fillGeneratedContractFields(inbound *contract.Inbound) error {
	for i := range inbound.Transports {
		transport := &inbound.Transports[i]
		switch transport.Type {
		case contract.TransportTLSAuto:
			if transport.TLSAuto == nil {
				continue
			}
			if err := fillContractTLSAuto(transport.TLSAuto); err != nil {
				return err
			}
		case contract.TransportReality:
			if transport.Reality == nil {
				continue
			}
			if err := fillContractReality(transport.Reality); err != nil {
				return err
			}
		}
	}
	return nil
}

func fillContractReality(config *contract.RealityTransport) error {
	if config.PrivateKey != "" {
		return nil
	}
	pri, pub, err := reality.GenerateKey()
	if err != nil {
		return err
	}
	config.PrivateKey = pri
	config.PublicKey = pub
	return nil
}

func fillContractTLSAuto(config *contract.TLSAutoTransport) error {
	if config.ECH != nil && config.ECH.Enabled {
		if config.ECH.OuterSNI == "" {
			config.ECH.OuterSNI = rand.Text()
		}
		var id [1]byte
		_, _ = rand.Read(id[:])
		private, echConfig, err := tls.NewECHConfig(id[0], []byte(config.ECH.OuterSNI))
		if err != nil {
			return err
		}
		config.ECH.ConfigBase64 = echConfig
		config.ECH.PrivateKeyBase64 = private.Bytes()
	}

	if len(config.CACertBase64) != 0 && len(config.CAKeyBase64) != 0 {
		if _, err := cert.ParseCa(config.CACertBase64, config.CAKeyBase64); err != nil {
			return fmt.Errorf("parse ca failed: %w", err)
		}
		return nil
	}

	log.Info("tls ca cert or key is empty, regenerate new ca")

	ca, err := cert.GenerateCa()
	if err != nil {
		return err
	}
	certBytes, err := ca.CertBytes()
	if err != nil {
		return err
	}
	keyBytes, err := ca.PrivateKeyBytes()
	if err != nil {
		return err
	}

	config.CACertBase64 = certBytes
	config.CAKeyBase64 = keyBytes
	return nil
}
