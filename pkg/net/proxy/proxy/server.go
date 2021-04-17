package proxy

type Server interface {
	SetProxy(Proxy)
	SetServer(host string) error
	Close() error
}
