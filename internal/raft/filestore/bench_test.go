package filestore

import (
	"fmt"
	"testing"

	"github.com/tarnan3751/password-vault/internal/raft"
)

// BenchmarkAppend measures Append on the real filesystem. With fsync the
// cost is dominated by the device's flush latency (F_FULLFSYNC on darwin);
// a batch costs about the same as a single entry, which is the point of
// group commit.
func BenchmarkAppend(b *testing.B) {
	for _, sync := range []bool{true, false} {
		for _, batch := range []int{1, 64} {
			name := fmt.Sprintf("fsync=%v/batch=%d/256B", sync, batch)
			b.Run(name, func(b *testing.B) {
				st, err := Open(b.TempDir(), Options{NoSync: !sync})
				if err != nil {
					b.Fatal(err)
				}
				defer st.Close()
				if _, _, _, err := st.Load(); err != nil {
					b.Fatal(err)
				}
				data := make([]byte, 256)
				ents := make([]raft.Entry, batch)
				next := uint64(1)
				b.SetBytes(int64(batch * len(data)))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for j := range ents {
						ents[j] = raft.Entry{Index: next, Term: 1, Data: data}
						next++
					}
					if err := st.Append(ents); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
