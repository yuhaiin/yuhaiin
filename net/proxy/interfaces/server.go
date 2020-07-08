package interfaces

type Server interface {
	UpdateListen(host string) error
	Close() error
}
