package backup

import "errors"

var ErrBusy = errors.New("a backup or restore operation is already in progress")
