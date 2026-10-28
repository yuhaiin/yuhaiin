package httpapi

import (
	"context"
	"errors"
	"net/http"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/certificate"
	"github.com/Asutorufa/yuhaiin/pkg/store/certificates"
)

type CertificateController interface {
	List(context.Context) ([]contract.Resource, error)
	Save(context.Context, contract.Config, uint64) (contract.Resource, error)
	Delete(context.Context, string, uint64) error
	Renew(context.Context, string, uint64) (contract.Resource, error)
	Providers(context.Context) ([]contract.DNSProvider, error)
	SaveProvider(context.Context, contract.ProviderWrite) (contract.DNSProvider, error)
	DeleteProvider(context.Context, string, uint64) error
	Events() []contract.Event
}

func certificateError(err error) error {
	if errors.Is(err, certificates.ErrConflict) {
		return &rpcError{status: http.StatusConflict, code: "conflict", message: err.Error()}
	}
	if errors.Is(err, certificates.ErrInUse) {
		return &rpcError{status: http.StatusConflict, code: "resource_in_use", message: err.Error()}
	}
	return badRequest(err)
}

func addCertificateRPCRoutes(handlers *v2Handlers, services V2Services) {
	service := func() (CertificateController, error) {
		if services.Certificates == nil {
			return nil, unavailable("certificate management is unavailable")
		}
		return services.Certificates, nil
	}
	addRPCRoute(handlers, v2CertificatesList, func(ctx context.Context, _ *emptyRequest) (*contract.Overview, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		resources, err := s.List(ctx)
		if err != nil {
			return nil, certificateError(err)
		}
		providers, err := s.Providers(ctx)
		if err != nil {
			return nil, certificateError(err)
		}
		return &contract.Overview{Certificates: resources, Providers: providers, Events: s.Events()}, nil
	})
	addRPCRoute(handlers, v2CertificateSave, func(ctx context.Context, r *contract.SaveRequest) (*contract.Resource, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		v, err := s.Save(ctx, r.Certificate, r.Revision)
		if err != nil {
			return nil, certificateError(err)
		}
		return &v, nil
	})
	addRPCRoute(handlers, v2CertificateDelete, func(ctx context.Context, r *contract.RevisionRequest) (*emptyResponse, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		if err := s.Delete(ctx, r.ID, r.Revision); err != nil {
			return nil, certificateError(err)
		}
		return new(emptyResponse), nil
	})
	addRPCRoute(handlers, v2CertificateRenew, func(ctx context.Context, r *contract.RevisionRequest) (*contract.Resource, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		v, err := s.Renew(ctx, r.ID, r.Revision)
		if err != nil {
			return nil, certificateError(err)
		}
		return &v, nil
	})
	addRPCRoute(handlers, v2CertificateProviderSave, func(ctx context.Context, r *contract.ProviderWrite) (*contract.DNSProvider, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		v, err := s.SaveProvider(ctx, *r)
		if err != nil {
			return nil, certificateError(err)
		}
		return &v, nil
	})
	addRPCRoute(handlers, v2CertificateProviderDelete, func(ctx context.Context, r *contract.RevisionRequest) (*emptyResponse, error) {
		s, err := service()
		if err != nil {
			return nil, err
		}
		if err := s.DeleteProvider(ctx, r.ID, r.Revision); err != nil {
			return nil, certificateError(err)
		}
		return new(emptyResponse), nil
	})
}
