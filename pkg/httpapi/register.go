package httpapi

import "net/http"

type RegisterFunc func(pattern string, handler func(http.ResponseWriter, *http.Request) error)

func requiredPathValue(r *http.Request, name string) (string, error) {
	value := r.PathValue(name)
	if value == "" {
		return "", &pathValueError{name: name}
	}
	return value, nil
}

type pathValueError struct {
	name string
}

func (e *pathValueError) Error() string {
	return "missing path value " + e.name
}
