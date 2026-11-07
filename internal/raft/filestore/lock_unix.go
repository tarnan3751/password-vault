//go:build darwin || linux || freebsd

package filestore

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// lockFile takes an exclusive flock(2) on name, creating it if needed. The
// lock belongs to the open file description, so it also excludes a second
// Store opened on the same directory within this process, and the kernel
// releases it when the process dies (no stale lock files after a crash).
func lockFile(name string) (io.Closer, error) {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, &os.PathError{Op: "flock", Path: name, Err: err}
	}
	return f, nil
}
