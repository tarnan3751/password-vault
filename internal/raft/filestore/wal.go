package filestore

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// WAL layout; see the package documentation for the full description.
const (
	walFileName    = "wal"
	walMagic       = "PVWL"
	walVersion     = 1
	walHeaderSize  = 28 // magic 4 | version 4 | base 8 | salt 8 | crc 4
	recHeaderSize  = 28 // plen 4 | pcrc 4 | first 8 | count 4 | kind 1 | zero 3 | hcrc 4
	entHeaderSize  = 13 // term 8 | type 1 | dlen 4
	recKindEntries = 1

	// recordSlack is the room a record has beyond one maximum-size entry,
	// so a maximal entry can still share a record with small ones.
	recordSlack = 1 << 20
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc32c(b []byte) uint32 { return crc32.Checksum(b, castagnoli) }

// limits bounds what the WAL reader accepts and the writer produces. They
// are fields rather than constants only so tests can exercise multi-record
// appends and the size checks without allocating hundreds of MiB.
type limits struct {
	maxEntry  int // largest Entry.Data
	maxRecord int // largest record payload
}

func defaultLimits() limits {
	return limits{maxEntry: MaxEntrySize, maxRecord: MaxEntrySize + entHeaderSize + recordSlack}
}

// walCodec frames records for one WAL file. Every record header CRC is
// seeded with the file's random salt. Two reasons:
//   - Entry data is supplied by vault clients. Without the salt a client
//     could upload a blob containing a byte-perfect record header; if a
//     crash then tore that write, the torn-tail scan below would find the
//     fake header and refuse to start the node. With the salt the header
//     CRC depends on a value the client never sees.
//   - Each rewrite of the WAL (Compact, InstallSnapshot) uses a new salt,
//     so bytes from an earlier generation of the file can never be
//     mistaken for records of the current one.
//
// This is defence in depth, not cryptography: the salt guards against
// accidents and blind forgery, not against someone who can read the disk.
type walCodec struct {
	salt    uint64
	saltCRC uint32 // CRC state after absorbing the salt bytes
}

func newWALCodec(salt uint64) walCodec {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], salt)
	return walCodec{salt: salt, saltCRC: crc32.Update(0, castagnoli, b[:])}
}

func (c walCodec) headerCRC(h []byte) uint32 {
	return crc32.Update(c.saltCRC, castagnoli, h[:recHeaderSize-4])
}

func encodeWALHeader(base, salt uint64) []byte {
	h := make([]byte, walHeaderSize)
	copy(h[0:4], walMagic)
	binary.LittleEndian.PutUint32(h[4:8], walVersion)
	binary.LittleEndian.PutUint64(h[8:16], base)
	binary.LittleEndian.PutUint64(h[16:24], salt)
	binary.LittleEndian.PutUint32(h[24:28], crc32c(h[:24]))
	return h
}

func decodeWALHeader(h []byte) (base, salt uint64, err error) {
	if len(h) < walHeaderSize {
		return 0, 0, corruptf("wal header truncated: file is %d bytes, header needs %d", len(h), walHeaderSize)
	}
	h = h[:walHeaderSize]
	if string(h[0:4]) != walMagic {
		return 0, 0, corruptf("wal: bad magic %q", h[0:4])
	}
	if got, want := binary.LittleEndian.Uint32(h[24:28]), crc32c(h[:24]); got != want {
		return 0, 0, corruptf("wal: header checksum mismatch")
	}
	if v := binary.LittleEndian.Uint32(h[4:8]); v != walVersion {
		return 0, 0, fmt.Errorf("%w: wal version %d (this binary reads %d)", ErrUnsupportedVersion, v, walVersion)
	}
	base = binary.LittleEndian.Uint64(h[8:16])
	if base == 0 {
		return 0, 0, corruptf("wal: header base index is 0")
	}
	return base, binary.LittleEndian.Uint64(h[16:24]), nil
}

// appendRecord appends to dst one framed record holding entries, which must
// be non-empty and contiguous.
func (c walCodec) appendRecord(dst []byte, entries []raft.Entry) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, recHeaderSize)...)
	for i := range entries {
		e := &entries[i]
		dst = binary.LittleEndian.AppendUint64(dst, e.Term)
		dst = append(dst, byte(e.Type))
		dst = binary.LittleEndian.AppendUint32(dst, uint32(len(e.Data)))
		dst = append(dst, e.Data...)
	}
	h := dst[start : start+recHeaderSize]
	payload := dst[start+recHeaderSize:]
	binary.LittleEndian.PutUint32(h[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(h[4:8], crc32c(payload))
	binary.LittleEndian.PutUint64(h[8:16], entries[0].Index)
	binary.LittleEndian.PutUint32(h[16:20], uint32(len(entries)))
	h[20] = recKindEntries
	binary.LittleEndian.PutUint32(h[24:28], c.headerCRC(h))
	return dst
}

// splitRecords groups entries into runs whose payload fits in one record.
// Normally that is a single run, so an Append is one write and one fsync.
func splitRecords(entries []raft.Entry, lim limits) [][]raft.Entry {
	var out [][]raft.Entry
	start, size := 0, 0
	for i := range entries {
		es := entHeaderSize + len(entries[i].Data)
		if i > start && size+es > lim.maxRecord {
			out = append(out, entries[start:i])
			start, size = i, 0
		}
		size += es
	}
	return append(out, entries[start:])
}

// record is a decoded record. Entry data aliases the buffer it was decoded
// from (capacity-limited, so an append by a caller cannot clobber the next
// entry).
type record struct {
	first   uint64
	entries []raft.Entry
	size    int64 // frame size: header + payload
}

// recordProblem describes why the bytes at some offset are not a valid
// record. definite problems can only be corruption (the header checksum
// matched, so those bytes were written by us, yet they are inconsistent);
// the others are what a torn write looks like and are classified by what
// follows them.
type recordProblem struct {
	reason   string
	definite bool
}

// decodeRecordAt decodes the record framed at buf[off:]. It never allocates
// based on a length field before checking that the length fits in buf.
func (c walCodec) decodeRecordAt(buf []byte, off int64, lim limits) (record, *recordProblem) {
	rem := int64(len(buf)) - off
	if rem < recHeaderSize {
		return record{}, &recordProblem{reason: fmt.Sprintf("truncated record header (%d of %d bytes)", rem, recHeaderSize)}
	}
	h := buf[off : off+recHeaderSize]
	if binary.LittleEndian.Uint32(h[24:28]) != c.headerCRC(h) {
		return record{}, &recordProblem{reason: "record header checksum mismatch"}
	}
	plen := int64(binary.LittleEndian.Uint32(h[0:4]))
	pcrc := binary.LittleEndian.Uint32(h[4:8])
	first := binary.LittleEndian.Uint64(h[8:16])
	count := uint64(binary.LittleEndian.Uint32(h[16:20]))
	switch {
	case h[20] != recKindEntries || h[21]|h[22]|h[23] != 0:
		return record{}, &recordProblem{reason: fmt.Sprintf("unknown record kind %d", h[20]), definite: true}
	case plen > int64(lim.maxRecord):
		return record{}, &recordProblem{reason: fmt.Sprintf("record payload length %d exceeds limit %d", plen, lim.maxRecord), definite: true}
	case count == 0 || count*entHeaderSize > uint64(plen):
		return record{}, &recordProblem{reason: fmt.Sprintf("record entry count %d inconsistent with payload length %d", count, plen), definite: true}
	case first == 0 || first+count-1 < first:
		return record{}, &recordProblem{reason: fmt.Sprintf("record index range [%d, +%d) invalid", first, count), definite: true}
	}
	if rem-recHeaderSize < plen {
		return record{}, &recordProblem{reason: fmt.Sprintf("record payload truncated (%d of %d bytes)", rem-recHeaderSize, plen)}
	}
	p := buf[off+recHeaderSize : off+recHeaderSize+plen]
	if crc32c(p) != pcrc {
		return record{}, &recordProblem{reason: "record payload checksum mismatch"}
	}
	// From here on the payload is exactly what we wrote, so any
	// inconsistency is corruption (or a bug), never a torn write.
	entries := make([]raft.Entry, count)
	for i := range entries {
		if len(p) < entHeaderSize {
			return record{}, &recordProblem{reason: "entry header overruns record payload", definite: true}
		}
		dlen := uint64(binary.LittleEndian.Uint32(p[9:13]))
		if dlen > uint64(lim.maxEntry) {
			return record{}, &recordProblem{reason: fmt.Sprintf("entry data length %d exceeds limit %d", dlen, lim.maxEntry), definite: true}
		}
		if dlen > uint64(len(p)-entHeaderSize) {
			return record{}, &recordProblem{reason: "entry data overruns record payload", definite: true}
		}
		e := &entries[i]
		e.Index = first + uint64(i)
		e.Term = binary.LittleEndian.Uint64(p[0:8])
		e.Type = raft.EntryType(p[8])
		if dlen > 0 {
			end := entHeaderSize + int(dlen)
			e.Data = p[entHeaderSize:end:end]
		}
		p = p[entHeaderSize+int(dlen):]
	}
	if len(p) != 0 {
		return record{}, &recordProblem{reason: fmt.Sprintf("%d stray bytes after the last entry of a record", len(p)), definite: true}
	}
	return record{first: first, entries: entries, size: recHeaderSize + plen}, nil
}

// findValidHeader returns the offset of the first authentic record header
// at or after from, or -1. It is the "is anything valid after the bad
// record?" test that separates a torn tail from mid-log corruption. A cheap
// filter on the fixed kind/zero bytes runs before the CRC, so the scan is a
// linear pass even over tens of MiB of garbage.
func (c walCodec) findValidHeader(buf []byte, from int64) int64 {
	for y := from; y+recHeaderSize <= int64(len(buf)); y++ {
		h := buf[y : y+recHeaderSize]
		if h[20] != recKindEntries || h[21]|h[22]|h[23] != 0 {
			continue
		}
		if binary.LittleEndian.Uint32(h[24:28]) == c.headerCRC(h) {
			return y
		}
	}
	return -1
}

// entryMeta is the in-memory index of one live log entry: its term and the
// record that holds it, so Compact can copy records without rescanning.
type entryMeta struct {
	term   uint64
	recOff int64
	recLen int64
}

// walContents is the result of parsing a WAL file.
type walContents struct {
	base, salt uint64
	first      uint64 // index of entries[0]; meaningful only if entries is non-empty
	entries    []raft.Entry
	metas      []entryMeta
	end        int64  // offset just past the last valid record
	torn       bool   // bytes from end onward are a torn tail
	tornReason string // why the record at end was rejected
	size       int64  // total file size
}

// firstIndex is the "f" of the recovery rule: the first on-disk log index,
// or for an empty log the index the next entry will get.
func (w *walContents) firstIndex() uint64 {
	if len(w.entries) > 0 {
		return w.first
	}
	return w.base
}

func (w *walContents) termAt(i uint64) (uint64, bool) {
	if len(w.entries) == 0 || i < w.first || i-w.first >= uint64(len(w.entries)) {
		return 0, false
	}
	return w.entries[i-w.first].Term, true
}

// parseWAL decodes a whole WAL file image.
//
// Records are applied in order. A record whose first index is below the
// current next index discards every entry from that index onward before
// its own entries are added: this is how conflict truncation is stored
// (see Store.Append). A record that starts beyond the next index is a gap,
// which is corruption.
//
// Torn tail vs corruption: when the record at offset X is not valid, the
// rest of the file is scanned for any authentic record header. If one is
// found, X is a damaged record in the middle of the log: an error. If none
// is found, the bytes from X on are the remains of an interrupted final
// write and are reported as torn (the caller truncates them). This is
// sound because the store never has more than one unsynced record in the
// file (see Store.Append), so a crash can only damage the last record.
func parseWAL(buf []byte, lim limits) (*walContents, error) {
	base, salt, err := decodeWALHeader(buf)
	if err != nil {
		return nil, err
	}
	c := newWALCodec(salt)
	w := &walContents{base: base, salt: salt, size: int64(len(buf))}
	next := base
	off := int64(walHeaderSize)
	for off < int64(len(buf)) {
		rec, prob := c.decodeRecordAt(buf, off, lim)
		if prob != nil {
			if prob.definite {
				return nil, corruptf("wal: record at offset %d: %s", off, prob.reason)
			}
			if y := c.findValidHeader(buf, off+1); y >= 0 {
				return nil, corruptf("wal: invalid record at offset %d (%s) is followed by a valid record at offset %d", off, prob.reason, y)
			}
			w.torn, w.tornReason = true, prob.reason
			break
		}
		if rec.first > next {
			return nil, corruptf("wal: record at offset %d starts at index %d but the log continues at %d", off, rec.first, next)
		}
		w.truncateFrom(rec.first)
		if len(w.entries) == 0 {
			w.first = rec.first
		}
		for i := range rec.entries {
			e := rec.entries[i]
			e.Data = bytes.Clone(e.Data) // do not pin the whole file image in memory
			w.entries = append(w.entries, e)
			w.metas = append(w.metas, entryMeta{term: e.Term, recOff: off, recLen: rec.size})
		}
		next = rec.first + uint64(len(rec.entries))
		off += rec.size
	}
	w.end = off
	return w, nil
}

// truncateFrom drops parsed entries with index >= i. Dropped slots are
// cleared so their data is not kept alive by the slice's spare capacity.
func (w *walContents) truncateFrom(i uint64) {
	var keep int
	switch {
	case len(w.entries) == 0:
		return
	case i <= w.first:
		keep = 0
	case i-w.first < uint64(len(w.entries)):
		keep = int(i - w.first)
	default:
		return
	}
	clear(w.entries[keep:])
	w.entries, w.metas = w.entries[:keep], w.metas[:keep]
}
