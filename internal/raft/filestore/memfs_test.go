package filestore

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
)

// memFS is a fault-injecting, single-directory, in-memory filesystem that
// models what a real disk may keep after a power failure:
//
//   - File data that was never fsynced may be lost. Each file keeps its
//     durable contents (as of its last Sync) plus the ordered list of writes
//     and truncates since then. On a crash a random prefix of that list
//     survives, and the first lost write may survive partially: any prefix
//     of its bytes, optionally followed by garbage (random bytes or zeros)
//     covering part of the rest of its range, which is what a file looks
//     like when its size reached the disk but its data did not.
//   - Directory changes (create, rename, remove) that were not followed by
//     a SyncDir may or may not survive, EACH INDEPENDENTLY. That is more
//     adversarial than a journaling filesystem (which keeps a prefix) and
//     checks that the store fsyncs the directory wherever order matters.
//     rename stays atomic: it either happened or did not.
//   - Any mutating call can be made to fail (crashAt / failAt), including
//     Sync, and a failed Sync leaves the data unsynced.
//
// After a crash every call on the old instance fails with errCrashed;
// Crash returns a new instance holding what survived.
type memFS struct {
	mu   sync.Mutex
	root string

	exists     bool
	cur        map[string]*memInode // what a process sees now
	dur        map[string]*memInode // directory as of the last SyncDir
	pendingDir []dirOp
	locks      map[string]bool

	// Fault injection. steps counts mutating operations (open with
	// O_CREATE/O_TRUNC, WriteAt, Truncate, Sync, SyncDir, Rename, Remove).
	steps        int
	crashAt      int  // crash at this step (0 = never)
	crashPerform bool // whether the crashing operation reaches volatile state first
	failAt       int  // fail this step with failErr (0 = never)
	failPerform  bool
	failErr      error
	failNextSync bool // the next file or directory Sync fails with errInjected, unperformed
	crashed      bool

	trace []string // recent operations, for failure messages
}

var (
	errCrashed  = errors.New("memfs: simulated power failure")
	errInjected = errors.New("memfs: injected I/O error")
)

type crashMode int

const (
	crashRandom   crashMode = iota
	crashKeepNone           // every unsynced change is lost
	crashKeepAll            // every unsynced change survives
)

func (c crashMode) String() string {
	return [...]string{"random", "keep-none", "keep-all"}[c]
}

type memInode struct {
	data    []byte  // volatile contents
	durable []byte  // contents as of the last Sync
	pending []memOp // changes since the last Sync, in order
	mode    os.FileMode
}

type memOp struct {
	trunc bool
	size  int64 // trunc
	off   int64 // write
	data  []byte
}

func applyOp(b []byte, op memOp) []byte {
	if op.trunc {
		if op.size <= int64(len(b)) {
			return b[:op.size]
		}
		return append(b, make([]byte, op.size-int64(len(b)))...)
	}
	if end := op.off + int64(len(op.data)); end > int64(len(b)) {
		b = append(b, make([]byte, end-int64(len(b)))...)
	}
	copy(b[op.off:], op.data)
	return b
}

func (n *memInode) apply(op memOp) {
	n.data = applyOp(n.data, op)
	n.pending = append(n.pending, op)
}

type dirOpKind int

const (
	dirCreate dirOpKind = iota
	dirRename
	dirRemove
)

type dirOp struct {
	kind     dirOpKind
	name, to string
	ino      *memInode
}

func newMemFS(root string) *memFS {
	return &memFS{
		root:  filepath.Clean(root),
		cur:   map[string]*memInode{},
		dur:   map[string]*memInode{},
		locks: map[string]bool{},
	}
}

func (m *memFS) tracef(format string, args ...any) {
	m.trace = append(m.trace, fmt.Sprintf("%d: ", m.steps)+fmt.Sprintf(format, args...))
	if len(m.trace) > 64 {
		m.trace = m.trace[len(m.trace)-64:]
	}
}

// step is called before every mutating operation. perform says whether the
// operation should take effect in volatile state (a crash can strike just
// after an operation reached the page cache, or just before).
func (m *memFS) step(what string) (perform bool, err error) {
	if m.crashed {
		return false, errCrashed
	}
	m.steps++
	switch {
	case m.failNextSync && strings.HasPrefix(what, "sync"):
		m.failNextSync = false
		m.tracef("FAIL %s", what)
		return false, errInjected
	case m.crashAt > 0 && m.steps >= m.crashAt:
		m.crashed = true
		m.tracef("CRASH during %s (performed=%v)", what, m.crashPerform)
		return m.crashPerform, errCrashed
	case m.failAt > 0 && m.steps == m.failAt:
		m.tracef("FAIL %s (performed=%v)", what, m.failPerform)
		return m.failPerform, m.failErr
	}
	m.tracef("%s", what)
	return true, nil
}

func (m *memFS) base(name string) (string, error) {
	if filepath.Dir(filepath.Clean(name)) != m.root {
		return "", &fs.PathError{Op: "memfs", Path: name, Err: errors.New("outside the store directory")}
	}
	if !m.exists {
		return "", &fs.PathError{Op: "memfs", Path: name, Err: fs.ErrNotExist}
	}
	return filepath.Base(name), nil
}

func (m *memFS) MkdirAll(dir string, perm os.FileMode) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crashed {
		return nil, errCrashed
	}
	if filepath.Clean(dir) != m.root {
		return nil, fmt.Errorf("memfs: only %s is supported", m.root)
	}
	if m.exists {
		return nil, nil
	}
	// The root's own durability is not modelled: it is created once, by
	// the first Open, before any state exists.
	m.exists = true
	return []string{m.root}, nil
}

func (m *memFS) OpenFile(name string, flag int, perm os.FileMode) (file, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crashed {
		return nil, errCrashed
	}
	b, err := m.base(name)
	if err != nil {
		return nil, err
	}
	ino, ok := m.cur[b]
	writable := flag&(os.O_WRONLY|os.O_RDWR) != 0
	switch {
	case !ok && flag&os.O_CREATE == 0:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	case ok && flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrExist}
	case !ok:
		perform, err := m.step("create " + b)
		if perform {
			ino = &memInode{mode: perm}
			m.cur[b] = ino
			m.pendingDir = append(m.pendingDir, dirOp{kind: dirCreate, name: b, ino: ino})
		}
		if err != nil {
			return nil, err
		}
	case flag&os.O_TRUNC != 0 && writable:
		perform, err := m.step("open-truncate " + b)
		if perform {
			ino.apply(memOp{trunc: true, size: 0})
		}
		if err != nil {
			return nil, err
		}
	}
	return &memFile{fs: m, ino: ino, name: b, writable: writable}, nil
}

func (m *memFS) ReadDir(dir string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crashed {
		return nil, errCrashed
	}
	if filepath.Clean(dir) != m.root || !m.exists {
		return nil, &fs.PathError{Op: "readdir", Path: dir, Err: fs.ErrNotExist}
	}
	return slices.Sorted(maps.Keys(m.cur)), nil
}

func (m *memFS) Rename(oldpath, newpath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crashed {
		return errCrashed
	}
	ob, err := m.base(oldpath)
	if err != nil {
		return err
	}
	nb, err := m.base(newpath)
	if err != nil {
		return err
	}
	ino, ok := m.cur[ob]
	if !ok {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: fs.ErrNotExist}
	}
	perform, err := m.step("rename " + ob + " -> " + nb)
	if perform {
		delete(m.cur, ob)
		m.cur[nb] = ino
		m.pendingDir = append(m.pendingDir, dirOp{kind: dirRename, name: ob, to: nb, ino: ino})
	}
	return err
}

func (m *memFS) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crashed {
		return errCrashed
	}
	b, err := m.base(name)
	if err != nil {
		return err
	}
	ino, ok := m.cur[b]
	if !ok {
		return &fs.PathError{Op: "remove", Path: name, Err: fs.ErrNotExist}
	}
	perform, err := m.step("remove " + b)
	if perform {
		delete(m.cur, b)
		m.pendingDir = append(m.pendingDir, dirOp{kind: dirRemove, name: b, ino: ino})
	}
	return err
}

func (m *memFS) SyncDir(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crashed {
		return errCrashed
	}
	dir = filepath.Clean(dir)
	if dir != m.root && dir != filepath.Dir(m.root) {
		return &fs.PathError{Op: "syncdir", Path: dir, Err: fs.ErrNotExist}
	}
	perform, err := m.step("syncdir " + dir)
	if perform && dir == m.root {
		m.dur = maps.Clone(m.cur)
		m.pendingDir = nil
	}
	return err
}

func (m *memFS) Lock(name string) (io.Closer, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crashed {
		return nil, errCrashed
	}
	b, err := m.base(name)
	if err != nil {
		return nil, err
	}
	if m.locks[b] {
		return nil, ErrLocked
	}
	m.locks[b] = true
	return closerFunc(func() error {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.locks, b)
		return nil
	}), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// Crash simulates a power failure and returns a filesystem holding what
// survived. rng drives the random choices of crashRandom.
func (m *memFS) Crash(rng *rand.Rand, mode crashMode) *memFS {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crashed = true
	keep := func() bool {
		switch mode {
		case crashKeepNone:
			return false
		case crashKeepAll:
			return true
		}
		return rng.IntN(2) == 0
	}
	dir := maps.Clone(m.dur)
	for _, op := range m.pendingDir {
		if !keep() {
			continue
		}
		switch op.kind {
		case dirCreate:
			dir[op.name] = op.ino
		case dirRename:
			dir[op.to] = op.ino
			if dir[op.name] == op.ino {
				delete(dir, op.name)
			}
		case dirRemove:
			if dir[op.name] == op.ino {
				delete(dir, op.name)
			}
		}
	}
	out := newMemFS(m.root)
	out.exists = m.exists
	fresh := map[*memInode]*memInode{}
	for _, name := range slices.Sorted(maps.Keys(dir)) { // sorted: rng use must be deterministic
		old := dir[name]
		n, ok := fresh[old]
		if !ok {
			c := old.crashContents(rng, mode)
			n = &memInode{data: c, durable: slices.Clone(c), mode: old.mode}
			fresh[old] = n
		}
		out.cur[name] = n
		out.dur[name] = n
	}
	return out
}

func (n *memInode) crashContents(rng *rand.Rand, mode crashMode) []byte {
	b := slices.Clone(n.durable)
	switch mode {
	case crashKeepNone:
		return b
	case crashKeepAll:
		for _, op := range n.pending {
			b = applyOp(b, op)
		}
		return b
	}
	k := rng.IntN(len(n.pending) + 1)
	for _, op := range n.pending[:k] {
		b = applyOp(b, op)
	}
	if k < len(n.pending) && !n.pending[k].trunc && rng.IntN(2) == 0 {
		op := n.pending[k]
		keepLen := rng.IntN(len(op.data) + 1)
		b = applyOp(b, memOp{off: op.off, data: op.data[:keepLen]})
		if rest := len(op.data) - keepLen; rest > 0 && rng.IntN(2) == 0 {
			g := make([]byte, 1+rng.IntN(rest))
			if rng.IntN(2) == 0 {
				for i := range g {
					g[i] = byte(rng.Uint32())
				}
			}
			b = applyOp(b, memOp{off: op.off + int64(keepLen), data: g})
		}
	}
	return b
}

// Helpers for tests that inspect or damage files directly. These bypass
// fault injection and make the change durable.

func (m *memFS) fileData(name string) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ino, ok := m.cur[name]
	if !ok {
		return nil, false
	}
	return slices.Clone(ino.data), true
}

func (m *memFS) setFileData(name string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exists = true
	ino, ok := m.cur[name]
	if !ok {
		ino = &memInode{mode: 0o600}
		m.cur[name] = ino
	}
	ino.data, ino.durable, ino.pending = slices.Clone(data), slices.Clone(data), nil
	m.dur = maps.Clone(m.cur)
	m.pendingDir = nil
}

func (m *memFS) removeFile(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cur, name)
	m.dur = maps.Clone(m.cur)
	m.pendingDir = nil
}

func (m *memFS) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Sorted(maps.Keys(m.cur))
}

func (m *memFS) describe() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var sb strings.Builder
	names := make([]string, 0, len(m.cur))
	for n := range m.cur {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&sb, "  %s (%d bytes)\n", n, len(m.cur[n].data))
	}
	sb.WriteString("  recent operations:\n")
	for _, t := range m.trace {
		sb.WriteString("    " + t + "\n")
	}
	return sb.String()
}

type memFile struct {
	fs       *memFS
	ino      *memInode
	name     string
	writable bool
	closed   bool
}

func (f *memFile) check() error {
	if f.fs.crashed {
		return errCrashed
	}
	if f.closed {
		return fs.ErrClosed
	}
	return nil
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if err := f.check(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, errors.New("memfs: negative offset")
	}
	if off >= int64(len(f.ino.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.ino.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if err := f.check(); err != nil {
		return 0, err
	}
	if !f.writable {
		return 0, errors.New("memfs: file not open for writing")
	}
	perform, err := f.fs.step(fmt.Sprintf("write %s [%d, %d)", f.name, off, off+int64(len(p))))
	if perform {
		f.ino.apply(memOp{off: off, data: slices.Clone(p)})
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *memFile) Truncate(size int64) error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if err := f.check(); err != nil {
		return err
	}
	perform, err := f.fs.step(fmt.Sprintf("truncate %s to %d", f.name, size))
	if perform {
		f.ino.apply(memOp{trunc: true, size: size})
	}
	return err
}

func (f *memFile) Sync() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if err := f.check(); err != nil {
		return err
	}
	perform, err := f.fs.step("sync " + f.name)
	if perform {
		f.ino.durable = slices.Clone(f.ino.data)
		f.ino.pending = nil
	}
	return err
}

func (f *memFile) Size() (int64, error) {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	if err := f.check(); err != nil {
		return 0, err
	}
	return int64(len(f.ino.data)), nil
}

func (f *memFile) Close() error {
	f.fs.mu.Lock()
	defer f.fs.mu.Unlock()
	f.closed = true
	return nil
}
