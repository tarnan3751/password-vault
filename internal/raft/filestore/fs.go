package filestore

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// fileSystem is the narrow set of filesystem operations the store performs.
// It exists so tests can substitute a fault-injecting in-memory filesystem
// that models what a real disk may lose on power failure (unsynced data,
// unsynced directory entries, failed fsyncs). Every durability decision in
// the store is expressed through it: data reaches the disk only via
// file.Sync, and a create/rename/remove only via SyncDir.
type fileSystem interface {
	// MkdirAll creates dir and any missing parents with perm. It returns the
	// directories it created, outermost first, so the caller can fsync
	// their parents.
	MkdirAll(dir string, perm os.FileMode) (created []string, err error)
	OpenFile(name string, flag int, perm os.FileMode) (file, error)
	// ReadDir returns the names of the entries in dir, sorted.
	ReadDir(dir string) ([]string, error)
	// Rename atomically replaces newpath with oldpath (POSIX rename(2)).
	Rename(oldpath, newpath string) error
	Remove(name string) error
	// SyncDir makes creations, renames and removals of entries in dir
	// durable.
	SyncDir(dir string) error
	// Lock takes an exclusive, non-blocking lock tied to the returned
	// Closer. It returns ErrLocked if the lock is already held.
	Lock(name string) (io.Closer, error)
}

// file is an open file. The store only uses positional I/O, so a file has
// no seek offset to get out of sync.
type file interface {
	io.ReaderAt
	io.WriterAt
	Truncate(size int64) error
	// Sync makes the file's data and size durable.
	Sync() error
	Size() (int64, error)
	Close() error
}

// osFS is the real filesystem.
//
// Durability on darwin: (*os.File).Sync is implemented by
// internal/poll.(*FD).Fsync, which on darwin issues fcntl(F_FULLFSYNC)
// (falling back to fsync(2) only when the filesystem returns ENOTSUP, e.g.
// some network mounts). Plain fsync(2) on macOS only hands data to the
// drive, which may keep it in a volatile cache; F_FULLFSYNC asks the drive
// to flush that cache. Checked against the Go 1.27 sources
// (src/internal/poll/fd_fsync_darwin.go). The same call is used for
// directories in SyncDir, so directory fsyncs get the same treatment. On
// linux (*os.File).Sync is fsync(2).
type osFS struct{}

func (osFS) MkdirAll(dir string, perm os.FileMode) ([]string, error) {
	dir = filepath.Clean(dir)
	// Find the missing ancestors first so that each newly created
	// directory's entry in its parent can be made durable afterwards.
	var missing []string
	for d := dir; ; {
		fi, err := os.Stat(d)
		if err == nil {
			if !fi.IsDir() {
				return nil, &fs.PathError{Op: "mkdir", Path: d, Err: errors.New("not a directory")}
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		missing = append(missing, d)
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	if len(missing) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return nil, err
	}
	// missing is innermost first; report outermost first.
	sort.Slice(missing, func(i, j int) bool { return len(missing[i]) < len(missing[j]) })
	return missing, nil
}

func (osFS) OpenFile(name string, flag int, perm os.FileMode) (file, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return osFile{f}, nil
}

func (osFS) ReadDir(dir string) ([]string, error) {
	des, err := os.ReadDir(dir) // sorted by name
	if err != nil {
		return nil, err
	}
	names := make([]string, len(des))
	for i, de := range des {
		names[i] = de.Name()
	}
	return names, nil
}

func (osFS) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (osFS) Remove(name string) error { return os.Remove(name) }

func (osFS) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync() // F_FULLFSYNC on darwin, fsync(2) on linux; see osFS.
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

func (osFS) Lock(name string) (io.Closer, error) { return lockFile(name) }

type osFile struct{ *os.File }

func (f osFile) Size() (int64, error) {
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return fi.Size(), nil
}

// readWhole reads the entire contents of f. The size comes from the file
// itself, never from a length field inside it, so a hostile or corrupt
// length cannot make this over-allocate.
func readWhole(f file) ([]byte, error) {
	size, err := f.Size()
	if err != nil {
		return nil, err
	}
	if size < 0 || int64(int(size)) != size {
		return nil, errors.New("file too large to read into memory")
	}
	buf := make([]byte, size)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !(errors.Is(err, io.EOF) && n == len(buf)) {
		return nil, err
	}
	return buf, nil
}
