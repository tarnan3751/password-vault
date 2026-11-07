package filestore

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/tarnan3751/password-vault/internal/raft"
)

const (
	snapMagic      = "PVSN"
	snapVersion    = 1
	snapHeaderSize = 40 // magic 4 | version 4 | index 8 | term 8 | dlen 8 | dcrc 4 | hcrc 4
	snapPrefix     = "snap-"
	snapSuffix     = ".snap"
)

// snapFile names one snapshot file. The sequence number orders snapshots
// by when they were saved (the contract's "latest" is the most recently
// saved, which in a correct core is also the highest index, but the store
// does not rely on that). Index and term are repeated in the name so that
// they are still known when the file's contents are corrupt; Load needs
// them to decide whether falling back to an older snapshot is safe.
type snapFile struct {
	name string
	seq  uint64
	meta raft.SnapshotMeta
}

func newSnapFile(seq uint64, m raft.SnapshotMeta) snapFile {
	return snapFile{
		name: fmt.Sprintf("%s%016x-%016x-%016x%s", snapPrefix, seq, m.Index, m.Term, snapSuffix),
		seq:  seq,
		meta: m,
	}
}

// parseSnapFileName accepts exactly the names newSnapFile produces.
func parseSnapFileName(name string) (snapFile, bool) {
	if !strings.HasPrefix(name, snapPrefix) || !strings.HasSuffix(name, snapSuffix) {
		return snapFile{}, false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, snapPrefix), snapSuffix), "-")
	if len(parts) != 3 {
		return snapFile{}, false
	}
	var v [3]uint64
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 16, 64)
		if len(p) != 16 || err != nil {
			return snapFile{}, false
		}
		v[i] = n
	}
	sf := newSnapFile(v[0], raft.SnapshotMeta{Index: v[1], Term: v[2]})
	if sf.name != name { // rejects upper-case hex and other non-canonical spellings
		return snapFile{}, false
	}
	return sf, true
}

func encodeSnapHeader(m raft.SnapshotMeta, data []byte) []byte {
	h := make([]byte, snapHeaderSize)
	copy(h[0:4], snapMagic)
	binary.LittleEndian.PutUint32(h[4:8], snapVersion)
	binary.LittleEndian.PutUint64(h[8:16], m.Index)
	binary.LittleEndian.PutUint64(h[16:24], m.Term)
	binary.LittleEndian.PutUint64(h[24:32], uint64(len(data)))
	binary.LittleEndian.PutUint32(h[32:36], crc32c(data))
	binary.LittleEndian.PutUint32(h[36:40], crc32c(h[:36]))
	return h
}

// decodeSnapshot verifies a whole snapshot file image against its expected
// name. The data length comes from the file size; the header's length
// field is only compared against it, never used to allocate.
func decodeSnapshot(b []byte, sf snapFile) (*raft.Snapshot, error) {
	if len(b) < snapHeaderSize {
		return nil, corruptf("snapshot %s: truncated header (%d bytes)", sf.name, len(b))
	}
	h := b[:snapHeaderSize]
	if string(h[0:4]) != snapMagic {
		return nil, corruptf("snapshot %s: bad magic %q", sf.name, h[0:4])
	}
	if binary.LittleEndian.Uint32(h[36:40]) != crc32c(h[:36]) {
		return nil, corruptf("snapshot %s: header checksum mismatch", sf.name)
	}
	if v := binary.LittleEndian.Uint32(h[4:8]); v != snapVersion {
		return nil, fmt.Errorf("%w: snapshot %s version %d (this binary reads %d)", ErrUnsupportedVersion, sf.name, v, snapVersion)
	}
	m := raft.SnapshotMeta{
		Index: binary.LittleEndian.Uint64(h[8:16]),
		Term:  binary.LittleEndian.Uint64(h[16:24]),
	}
	if m != sf.meta {
		return nil, corruptf("snapshot %s: header says index %d term %d", sf.name, m.Index, m.Term)
	}
	data := b[snapHeaderSize:]
	if dlen := binary.LittleEndian.Uint64(h[24:32]); dlen != uint64(len(data)) {
		return nil, corruptf("snapshot %s: header says %d data bytes, file has %d", sf.name, dlen, len(data))
	}
	if binary.LittleEndian.Uint32(h[32:36]) != crc32c(data) {
		return nil, corruptf("snapshot %s: data checksum mismatch", sf.name)
	}
	return &raft.Snapshot{Meta: m, Data: data}, nil
}
