package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
	"github.com/tarnan3751/password-vault/web"
)

// Benchmarks of what every request pays and of the sync handler, against
// the fake Raft node (no network, no disk):
//
//	go test ./internal/server -run '^$' -bench . -benchmem

type benchEnv struct {
	srv  *Server
	sm   *fsm.FSM
	node *fakeNode
	user *account
}

func newBenchEnv(b *testing.B, items int, webFS fs.FS) *benchEnv {
	b.Helper()
	sm := fsm.New()
	node := newFakeNode(sm)
	clock := &fakeClock{t: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	cfg := Config{NodeID: "n1", Raft: node, FSM: sm, Peers: testPeers, BootstrapToken: testBootstrapToken, Now: clock.Now}
	cfg.WebFS = webFS
	srv, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	cmd, _ := fsm.EncodeCommand(fmt.Sprintf("%032x", 1), clock.Now().UnixMilli(), "", 0, &fsm.InitArgs{ClusterKey: bytes.Repeat([]byte{0x42}, 32)})
	node.apply(cmd)
	e := &benchEnv{srv: srv, sm: sm, node: node, user: newAccount("alice")}
	var lr api.LoginResponse
	e.mustDo(b, "POST", "/v1/register", e.user.registerReq(testBootstrapToken), 200, &lr)
	e.user.token = lr.Token
	for i := 0; i < items; i++ {
		// Applied directly: the benchmark is about reading them.
		c, _ := fsm.EncodeCommand(fmt.Sprintf("%032x", 1000+i), clock.Now().UnixMilli(), e.user.id, 1,
			&fsm.PutItemArgs{VaultID: e.user.personal, ItemID: fmt.Sprintf("%032x", i*7919%1_000_003), Blob: box(768), KeyEpoch: 1})
		if r, _ := fsm.DecodeResult(node.apply(c)); r.Err != nil {
			b.Fatal(r.Err.Message)
		}
	}
	return e
}

func (e *benchEnv) do(method, path string, body any, hdr ...string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (e *benchEnv) mustDo(b *testing.B, method, path string, body any, want int, out any, hdr ...string) {
	b.Helper()
	rec := e.do(method, path, body, hdr...)
	if rec.Code != want {
		b.Fatalf("%s %s: %d: %s", method, path, rec.Code, rec.Body.Bytes())
	}
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSync is GET /v1/sync: a full download of a vault of n entries,
// and the common case of a device polling with ?since=<current rev>.
func BenchmarkSync(b *testing.B) {
	for _, n := range []int{1000, 5000} {
		b.Run(fmt.Sprintf("full-%d", n), func(b *testing.B) {
			e := newBenchEnv(b, n, nil)
			auth := "Bearer " + e.user.token
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if rec := e.do("GET", "/v1/sync", nil, "Authorization", auth); rec.Code != 200 {
					b.Fatal(rec.Code)
				}
			}
		})
	}
	b.Run("unchanged", func(b *testing.B) {
		e := newBenchEnv(b, 1000, nil)
		auth := "Bearer " + e.user.token
		path := fmt.Sprintf("/v1/sync?since=%d", e.sm.Rev())
		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			if rec := e.do("GET", path, nil, "Authorization", auth); rec.Code != 200 {
				b.Fatal(rec.Code)
			}
		}
	})
}

// BenchmarkPutItem is one item write through the handler (decode, validate,
// encode the command, apply, respond).
func BenchmarkPutItem(b *testing.B) {
	e := newBenchEnv(b, 1000, nil)
	auth := "Bearer " + e.user.token
	path := "/v1/vaults/" + e.user.personal + "/items/" + fmt.Sprintf("%032x", 0)
	req := api.PutItemRequest{Blob: box(768), BaseVersion: e.sm.Rev() - 999, KeyEpoch: 1} // item 0 was the first written
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		body, _ := json.Marshal(req)
		r := httptest.NewRequest("PUT", path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", auth)
		rec := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(rec, r)
		if rec.Code != 200 {
			b.Fatal(rec.Code, rec.Body.String())
		}
		var mr api.MutationResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &mr)
		req.BaseVersion = mr.Version
	}
}

// BenchmarkStatic is a browser loading the real embedded client (web/dist):
// the first visit (every file, gzip accepted), and a visit more than an
// hour later, when everything not marked immutable is requested again,
// conditionally if the first response carried an entity tag. wire-bytes is
// the response bodies sent.
func BenchmarkStatic(b *testing.B) {
	dist := web.Dist()
	var paths []string
	_ = fs.WalkDir(dist, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			paths = append(paths, "/"+strings.TrimSuffix(p, "index.html"))
		}
		return nil
	})
	e := newBenchEnv(b, 0, dist)
	const accept = "gzip, deflate, br, zstd"
	revalidate := map[string]string{} // path -> entity tag ("" if none)
	for _, p := range paths {
		rec := e.do("GET", p, nil, "Accept-Encoding", accept)
		if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
			revalidate[p] = rec.Header().Get("ETag")
		}
	}
	b.Run("first-load", func(b *testing.B) {
		b.ReportAllocs()
		var wire int
		for range b.N {
			wire = 0
			for _, p := range paths {
				rec := e.do("GET", p, nil, "Accept-Encoding", accept)
				if rec.Code != 200 {
					b.Fatal(p, rec.Code)
				}
				wire += rec.Body.Len()
			}
		}
		b.ReportMetric(float64(wire), "wire-bytes")
	})
	b.Run("repeat-load", func(b *testing.B) {
		b.ReportAllocs()
		var wire int
		for range b.N {
			wire = 0
			for p, tag := range revalidate {
				hdr := []string{"Accept-Encoding", accept}
				if tag != "" {
					hdr = append(hdr, "If-None-Match", tag)
				}
				wire += e.do("GET", p, nil, hdr...).Body.Len()
			}
		}
		b.ReportMetric(float64(wire), "wire-bytes")
		b.ReportMetric(float64(len(revalidate)), "requests")
	})
}
