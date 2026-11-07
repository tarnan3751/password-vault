//go:build !(darwin || linux || freebsd)

package filestore

import (
	"errors"
	"io"
)

// lockFile is not implemented on this platform. Refusing to open is safer
// than running two stores on one directory unguarded.
func lockFile(name string) (io.Closer, error) {
	return nil, errors.New("filestore: directory locking is not supported on this platform")
}
