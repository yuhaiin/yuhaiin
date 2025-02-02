package config

type DB interface {
	Batch(f ...func(*Setting) error) error
	View(f ...func(*Setting) error) error
	Dir() string
}
