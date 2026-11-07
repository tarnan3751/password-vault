package filestore

import (
	"encoding/binary"
	"fmt"

	"github.com/tarnan3751/password-vault/internal/raft"
)

const (
	hsFileName   = "hardstate"
	hsMagic      = "PVHS"
	hsVersion    = 1
	hsFixedSize  = 4 + 4 + 8 + 4 + 4 // magic | version | term | vlen | ... | crc
	maxVotedFor  = 4096              // node IDs are short; anything longer is corruption
	maxHSFileLen = hsFixedSize + maxVotedFor
)

func encodeHardState(hs raft.HardState) []byte {
	b := make([]byte, 0, hsFixedSize+len(hs.VotedFor))
	b = append(b, hsMagic...)
	b = binary.LittleEndian.AppendUint32(b, hsVersion)
	b = binary.LittleEndian.AppendUint64(b, hs.Term)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(hs.VotedFor)))
	b = append(b, hs.VotedFor...)
	return binary.LittleEndian.AppendUint32(b, crc32c(b))
}

func decodeHardState(b []byte) (raft.HardState, error) {
	if len(b) < hsFixedSize || len(b) > maxHSFileLen {
		return raft.HardState{}, corruptf("hardstate: file length %d out of range", len(b))
	}
	if string(b[0:4]) != hsMagic {
		return raft.HardState{}, corruptf("hardstate: bad magic %q", b[0:4])
	}
	body, sum := b[:len(b)-4], binary.LittleEndian.Uint32(b[len(b)-4:])
	if crc32c(body) != sum {
		return raft.HardState{}, corruptf("hardstate: checksum mismatch")
	}
	if v := binary.LittleEndian.Uint32(b[4:8]); v != hsVersion {
		return raft.HardState{}, fmt.Errorf("%w: hardstate version %d (this binary reads %d)", ErrUnsupportedVersion, v, hsVersion)
	}
	vlen := binary.LittleEndian.Uint32(b[16:20])
	if uint64(vlen) != uint64(len(b)-hsFixedSize) {
		return raft.HardState{}, corruptf("hardstate: votedFor length %d does not match file length %d", vlen, len(b))
	}
	return raft.HardState{
		Term:     binary.LittleEndian.Uint64(b[8:16]),
		VotedFor: string(b[20 : 20+vlen]),
	}, nil
}
