// Package filestore is the crash-safe, on-disk raft.Storage used by vaultd.
//
// Everything lives in one directory (mode 0700; every file 0600, because
// snapshots and log entries hold password verifier hashes and ciphertext):
//
//	LOCK                            flock(2)ed while a Store is open
//	hardstate                       term and vote; replaced atomically
//	wal                             the write-ahead log of entries
//	snap-<seq>-<index>-<term>.snap  snapshots (16-digit lower-case hex);
//	                                the highest <seq> is the latest
//	*.tmp                           an atomic replace in progress; deleted by Open
//
// Integers are little-endian. CRC is CRC-32C (Castagnoli).
//
// # WAL
//
// A 28-byte header followed by records:
//
//	header  magic "PVWL" | version u32 = 1 | base u64 | salt u64 | crc u32
//	record  plen u32 | pcrc u32 | first u64 | count u32 | kind u8 = 1 | 0 0 0 | hcrc u32 | payload
//	payload count x ( term u64 | type u8 | dlen u32 | data )
//
// The header crc covers the 24 bytes before it. hcrc = CRC(salt || the 24
// record header bytes before it); pcrc = CRC(payload). base is the index the
// next entry gets while the file holds no records (1 for a new store,
// snapshot index + 1 after Compact or InstallSnapshot). salt is random per
// file generation.
//
// One Append call is one record (split only beyond about MaxEntrySize).
// Records are applied in order: a record whose first index is at or below
// the current last index first discards every entry from first onward
// (conflict truncation stored logically, in the same record as the new
// entries), then appends its own. A record may not start beyond the next
// index (a gap is corruption).
//
// The file is append-only between rewrites. Compact and InstallSnapshot
// write a complete replacement under wal.tmp, fsync it, rename it over wal
// and fsync the directory.
//
// Damage is classified when reading: if the record at offset X fails to
// verify and no authentic record header (salted hcrc) appears anywhere
// after X, the bytes from X on are a torn final write and are truncated. If
// an authentic header follows, or a record that passed its checksums is
// internally inconsistent, or the file header is bad, Load fails with an
// error wrapping ErrCorrupt and changes nothing.
//
// # Hard state
//
//	magic "PVHS" | version u32 = 1 | term u64 | vlen u32 | votedFor [vlen] | crc u32
//
// crc covers everything before it.
//
// # Snapshots
//
//	magic "PVSN" | version u32 = 1 | index u64 | term u64 | dlen u64 | dcrc u32 | hcrc u32 | data [dlen]
//
// dcrc = CRC(data); hcrc covers the 36 header bytes before it. The index
// and term must match the file name and dlen must match the file size. The
// current snapshot and the one before it are kept; older ones are deleted
// once a newer one is durable.
//
// # Recovery
//
// Load applies the recovery rule of raft.Storage to the newest snapshot
// that verifies and the parsed log, and then makes the disk agree with what
// it returns: it truncates a torn WAL tail, or replaces the WAL with an
// empty one when the rule discards the log (only possible after a crash
// inside InstallSnapshot). It falls back to an older snapshot only when
// the log provably still covers everything the corrupt newer one did (see
// checkFallback). Mutating methods refuse, with an error and no I/O, calls
// that would leave a state the recovery rule would not return unchanged.
//
// # Assumptions about the platform
//
// fsync (F_FULLFSYNC on darwin) on a file makes its data and size durable;
// fsync on a directory makes creates, renames and removals in it durable;
// rename(2) is atomic. Writes that were never fsynced may be lost in whole
// or in part, and the lost part may read back as garbage, but the
// filesystem does not resurrect bytes from before a truncation that was
// itself fsynced (true of ext4 data=ordered, XFS, btrfs and APFS).
package filestore
