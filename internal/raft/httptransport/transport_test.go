package httptransport

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/tlsutil"
)

// swap lets a test replace a server's behaviour after the URL is known.
type swap struct{ h atomic.Pointer[http.Handler] }

func (s *swap) ServeHTTP(w http.ResponseWriter, r *http.Request) { (*s.h.Load()).ServeHTTP(w, r) }
func (s *swap) set(h http.Handler)                               { s.h.Store(&h) }

type recorder struct {
	mu   sync.Mutex
	msgs []raft.Message
}

func (r *recorder) add(m raft.Message) { r.mu.Lock(); r.msgs = append(r.msgs, m); r.mu.Unlock() }
func (r *recorder) all() []raft.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]raft.Message(nil), r.msgs...)
}
func (r *recorder) n() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.msgs) }

type node struct {
	id  string
	tr  *Transport
	srv *httptest.Server
	sw  *swap
	rec *recorder
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// cluster starts servers for ids, then a transport per id knowing the others.
func cluster(t *testing.T, ids []string, mod func(*Options)) map[string]*node {
	t.Helper()
	nodes := map[string]*node{}
	urls := map[string]string{}
	for _, id := range ids {
		n := &node{id: id, sw: &swap{}, rec: &recorder{}}
		n.sw.set(http.NotFoundHandler())
		n.srv = httptest.NewServer(n.sw)
		t.Cleanup(n.srv.Close)
		nodes[id] = n
		urls[id] = n.srv.URL
	}
	for _, id := range ids {
		o := Options{LocalID: id, Peers: urls}
		if mod != nil {
			mod(&o)
		}
		tr, err := New(o)
		if err != nil {
			t.Fatal(err)
		}
		n := nodes[id]
		n.tr = tr
		tr.SetHandler(n.rec.add)
		n.sw.set(tr.Handler())
		t.Cleanup(func() { tr.Close() })
	}
	return nodes
}

func msg(from, to string, term uint64) raft.Message {
	return raft.Message{Type: raft.MsgApp, From: from, To: to, Term: term}
}

func TestThreeNodesExchange(t *testing.T) {
	ns := cluster(t, []string{"a", "b", "c"}, nil)
	for from, n := range ns {
		var out []raft.Message
		for to := range ns {
			out = append(out, raft.Message{From: from, To: to, Term: 7, Entries: []raft.Entry{{Index: 1, Term: 7, Data: []byte(from + to)}}})
		}
		n.tr.Send(out) // includes a message to self, which must be dropped
	}
	for id, n := range ns {
		n := n
		waitFor(t, id+" receives 2 messages", func() bool { return n.rec.n() == 2 })
		for _, m := range n.rec.all() {
			if m.To != id || m.From == id || string(m.Entries[0].Data) != m.From+id {
				t.Errorf("%s got bad message %+v", id, m)
			}
		}
	}
	time.Sleep(50 * time.Millisecond)
	for id, n := range ns {
		if n.rec.n() != 2 {
			t.Errorf("%s got %d messages, want exactly 2", id, n.rec.n())
		}
	}
}

func TestOrderingPerPeer(t *testing.T) {
	ns := cluster(t, []string{"a", "b"}, func(o *Options) { o.QueueSize = 5000; o.MaxBatchBytes = 4096 })
	const N = 2000
	for i := 1; i <= N; i++ {
		ns["a"].tr.Send([]raft.Message{msg("a", "b", uint64(i))})
	}
	waitFor(t, "all delivered", func() bool { return ns["b"].rec.n() == N })
	for i, m := range ns["b"].rec.all() {
		if m.Term != uint64(i+1) {
			t.Fatalf("out of order at %d: term %d", i, m.Term)
		}
	}
}

func TestDropWhenDownAndRecover(t *testing.T) {
	ns := cluster(t, []string{"a", "b"}, nil)
	ns["b"].sw.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 1)})
	waitFor(t, "failure counted", func() bool { return ns["a"].tr.Stats()["b"].Failed >= 1 })
	if ns["b"].rec.n() != 0 {
		t.Fatal("delivered while down")
	}
	// Recover: the failed message is gone (no retry); new ones flow after backoff.
	ns["b"].sw.set(ns["b"].tr.Handler())
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 2)})
	waitFor(t, "delivery after recovery", func() bool { return ns["b"].rec.n() >= 1 })
	for _, m := range ns["b"].rec.all() {
		if m.Term == 1 {
			t.Error("dropped message was retried")
		}
	}
	if s := ns["a"].tr.Stats()["b"]; s.Sent == 0 {
		t.Errorf("stats: %+v", s)
	}
}

func TestSendNeverBlocksWithHangingPeer(t *testing.T) {
	release := make(chan struct{})
	ns := cluster(t, []string{"a", "b"}, func(o *Options) { o.RequestTimeout = 30 * time.Second })
	var inflight atomic.Int32
	ns["b"].sw.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer close(release)
	start := time.Now()
	for i := 0; i < 20000; i++ {
		ns["a"].tr.Send([]raft.Message{msg("a", "b", uint64(i))})
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Send blocked: %v", d)
	}
	waitFor(t, "request in flight", func() bool { return inflight.Load() == 1 })
	if s := ns["a"].tr.Stats()["b"]; s.Dropped == 0 {
		t.Errorf("expected drops, got %+v", s)
	}
	// Close must also return promptly despite the hung request.
	done := make(chan struct{})
	go func() { ns["a"].tr.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
}

func TestQueueOverflowDropsOldest(t *testing.T) {
	release := make(chan struct{})
	ns := cluster(t, []string{"a", "b"}, func(o *Options) { o.QueueSize = 10 })
	var started atomic.Int32
	inner := ns["b"].tr.Handler()
	ns["b"].sw.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if started.Add(1) == 1 {
			<-release // hold the first request so later messages queue up
		}
		inner.ServeHTTP(w, r)
	}))
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 0)})
	waitFor(t, "first request in flight", func() bool { return started.Load() == 1 })
	for i := 1; i <= 100; i++ {
		ns["a"].tr.Send([]raft.Message{msg("a", "b", uint64(i))})
	}
	if d := ns["a"].tr.Stats()["b"].Dropped; d != 90 {
		t.Errorf("dropped = %d, want 90", d)
	}
	close(release)
	waitFor(t, "11 delivered", func() bool { return ns["b"].rec.n() == 11 })
	got := ns["b"].rec.all()
	if got[0].Term != 0 {
		t.Errorf("first = %d", got[0].Term)
	}
	for i, m := range got[1:] {
		if m.Term != uint64(91+i) {
			t.Fatalf("kept wrong messages: idx %d term %d (want newest 91..100)", i, m.Term)
		}
	}
}

func TestBatching(t *testing.T) {
	release := make(chan struct{})
	ns := cluster(t, []string{"a", "b"}, nil)
	var reqs atomic.Int32
	inner := ns["b"].tr.Handler()
	ns["b"].sw.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reqs.Add(1) == 1 {
			<-release
		}
		inner.ServeHTTP(w, r)
	}))
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 0)})
	waitFor(t, "first in flight", func() bool { return reqs.Load() == 1 })
	var batch []raft.Message
	for i := 1; i <= 100; i++ {
		batch = append(batch, msg("a", "b", uint64(i)))
	}
	ns["a"].tr.Send(batch)
	close(release)
	waitFor(t, "101 delivered", func() bool { return ns["b"].rec.n() == 101 })
	if r := reqs.Load(); r != 2 {
		t.Errorf("requests = %d, want 2 (one in flight + one batch)", r)
	}
}

func TestBatchSizeCap(t *testing.T) {
	release := make(chan struct{})
	ns := cluster(t, []string{"a", "b"}, func(o *Options) { o.MaxBatchBytes = 100 << 10 })
	var reqs atomic.Int32
	inner := ns["b"].tr.Handler()
	ns["b"].sw.set(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reqs.Add(1) == 1 {
			<-release
		}
		inner.ServeHTTP(w, r)
	}))
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 0)})
	waitFor(t, "first in flight", func() bool { return reqs.Load() == 1 })
	big := make([]byte, 60<<10)
	for i := 1; i <= 4; i++ {
		ns["a"].tr.Send([]raft.Message{{From: "a", To: "b", Term: uint64(i), Data: big}})
	}
	close(release)
	waitFor(t, "5 delivered", func() bool { return ns["b"].rec.n() == 5 })
	if r := reqs.Load(); r != 5 { // 1 + four 60KiB messages, each over half the cap
		t.Errorf("requests = %d, want 5", r)
	}
}

func TestLargeMessage(t *testing.T) {
	ns := cluster(t, []string{"a", "b"}, nil)
	data := make([]byte, 20<<20)
	for i := range data {
		data[i] = byte(i * 31)
	}
	ns["a"].tr.Send([]raft.Message{{Type: raft.MsgSnap, From: "a", To: "b", Term: 3, Snap: &raft.Snapshot{Meta: raft.SnapshotMeta{Index: 9, Term: 3}, Data: data}}})
	waitFor(t, "snapshot delivered", func() bool { return ns["b"].rec.n() == 1 })
	m := ns["b"].rec.all()[0]
	if m.Snap == nil || !bytes.Equal(m.Snap.Data, data) || m.Snap.Meta.Index != 9 {
		t.Fatal("snapshot corrupted")
	}
}

// rawPost sends an arbitrary body to n's handler directly.
func rawPost(h http.Handler, method string, body []byte, mut func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, Path, bytes.NewReader(body))
	if mut != nil {
		mut(req)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func encode(t *testing.T, h header, msgs []raft.Message) []byte {
	t.Helper()
	var b bytes.Buffer
	e := gob.NewEncoder(&b)
	if err := e.Encode(h); err != nil {
		t.Fatal(err)
	}
	if err := e.Encode(msgs); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestInboundValidation(t *testing.T) {
	var got atomic.Int32
	tr, err := New(Options{LocalID: "a", Peers: map[string]string{"a": "http://x", "b": "http://127.0.0.1:1", "c": "http://127.0.0.1:1"}, MaxBodyBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	tr.SetHandler(func(raft.Message) { got.Add(1) })
	h := tr.Handler()
	ok := header{Version: wireVersion, From: "b", To: "a"}
	good := msg("b", "a", 1)

	cases := []struct {
		name   string
		method string
		body   []byte
		want   []int
	}{
		{"valid", "POST", encode(t, ok, []raft.Message{good, good}), []int{204}},
		{"wrong method", "GET", nil, []int{405}},
		{"wrong To", "POST", encode(t, header{wireVersion, "b", "c"}, []raft.Message{good}), []int{400}},
		{"unknown From", "POST", encode(t, header{wireVersion, "zed", "a"}, []raft.Message{msg("zed", "a", 1)}), []int{403}},
		{"self as From", "POST", encode(t, header{wireVersion, "a", "a"}, []raft.Message{msg("a", "a", 1)}), []int{403}},
		{"spoofed message From", "POST", encode(t, ok, []raft.Message{good, msg("c", "a", 1)}), []int{403}},
		{"wrong message To", "POST", encode(t, ok, []raft.Message{msg("b", "c", 1)}), []int{403}},
		{"bad version", "POST", encode(t, header{99, "b", "a"}, nil), []int{400}},
		{"garbage", "POST", []byte("this is not gob \x00\xff\xfe"), []int{400}},
		{"empty", "POST", nil, []int{400}},
		{"truncated", "POST", encode(t, ok, []raft.Message{good})[:20], []int{400}},
		{"oversize", "POST", encode(t, ok, []raft.Message{{From: "b", To: "a", Data: make([]byte, 2<<20)}}), []int{413, 400}},
	}
	for _, c := range cases {
		before := got.Load()
		rr := rawPost(h, c.method, c.body, nil)
		match := false
		for _, w := range c.want {
			match = match || rr.Code == w
		}
		if !match {
			t.Errorf("%s: status %d, want one of %v", c.name, rr.Code, c.want)
		}
		delivered := got.Load() - before
		if c.want[0] == 204 && delivered != 2 || c.want[0] != 204 && delivered != 0 {
			t.Errorf("%s: delivered %d messages", c.name, delivered)
		}
	}
	// No handler installed yet => 503.
	tr2, _ := New(Options{LocalID: "a", Peers: map[string]string{"b": "http://127.0.0.1:1"}})
	defer tr2.Close()
	if rr := rawPost(tr2.Handler(), "POST", encode(t, ok, nil), nil); rr.Code != 503 {
		t.Errorf("no handler: %d", rr.Code)
	}
}

func TestCloseSemantics(t *testing.T) {
	ns := cluster(t, []string{"a", "b"}, nil)
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 1)})
	waitFor(t, "delivered", func() bool { return ns["b"].rec.n() == 1 })

	if err := ns["b"].tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ns["b"].tr.Close(); err != nil { // idempotent
		t.Fatal(err)
	}
	rr := rawPost(ns["b"].tr.Handler(), "POST", encode(t, header{wireVersion, "a", "b"}, nil), nil)
	if rr.Code != 503 {
		t.Errorf("handler after Close = %d", rr.Code)
	}
	// Posting over the network to a closed peer must be a failure, not a delivery.
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 2)})
	waitFor(t, "failure", func() bool { return ns["a"].tr.Stats()["b"].Failed >= 1 })
	if ns["b"].rec.n() != 1 {
		t.Error("closed transport delivered a message")
	}

	ns["a"].tr.Close()
	before := ns["a"].tr.Stats()["b"]
	ns["a"].tr.Send([]raft.Message{msg("a", "b", 3)}) // no-op, must not panic
	after := ns["a"].tr.Stats()["b"]
	if after.Sent != before.Sent || after.Failed != before.Failed {
		t.Error("Send after Close was attempted")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("empty LocalID accepted")
	}
	if _, err := New(Options{LocalID: "a", Peers: map[string]string{"b": ""}}); err == nil {
		t.Error("empty peer URL accepted")
	}
}

// ---- mTLS ----

type tlsEnv struct {
	dir   string
	ca    string
	caPEM []byte
	caKey []byte
}

func newTLSEnv(t *testing.T) *tlsEnv {
	t.Helper()
	c, k, err := tlsutil.GenerateCA("test", 0)
	if err != nil {
		t.Fatal(err)
	}
	e := &tlsEnv{dir: t.TempDir(), caPEM: c, caKey: k}
	e.ca = filepath.Join(e.dir, "ca.pem")
	if err := tlsutil.WriteCertFile(e.ca, c); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *tlsEnv) files(t *testing.T, id string) (cert, key string) {
	t.Helper()
	c, k, err := tlsutil.GenerateNodeCert(e.caPEM, e.caKey, id, []string{"127.0.0.1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	cert, key = filepath.Join(e.dir, id+".crt"), filepath.Join(e.dir, id+".key")
	tlsutil.WriteCertFile(cert, c)
	tlsutil.WriteKeyFile(key, k)
	return
}

func (e *tlsEnv) client(t *testing.T, id string) (*http.Client, *tls.Config) {
	t.Helper()
	c, k := e.files(t, id)
	cfg, err := tlsutil.PeerClientConfig(e.ca, c, k)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}, cfg
}

func TestMTLSTransportAndIdentity(t *testing.T) {
	env := newTLSEnv(t)
	ids := []string{"a", "b", "c"}
	nodes := map[string]*node{}
	urls := map[string]string{}
	for _, id := range ids {
		n := &node{id: id, sw: &swap{}, rec: &recorder{}}
		n.sw.set(http.NotFoundHandler())
		c, k := env.files(t, id)
		cfg, err := tlsutil.PeerServerConfig(env.ca, c, k)
		if err != nil {
			t.Fatal(err)
		}
		n.srv = httptest.NewUnstartedServer(n.sw)
		n.srv.TLS = cfg
		n.srv.StartTLS()
		t.Cleanup(n.srv.Close)
		nodes[id], urls[id] = n, n.srv.URL
	}
	for _, id := range ids {
		cl, _ := env.client(t, id)
		tr, err := New(Options{LocalID: id, Peers: urls, Client: cl, RequireTLSIdentity: true})
		if err != nil {
			t.Fatal(err)
		}
		n := nodes[id]
		n.tr = tr
		tr.SetHandler(n.rec.add)
		n.sw.set(tr.Handler())
		t.Cleanup(func() { tr.Close() })
	}

	// Legitimate traffic works end to end over mTLS.
	nodes["a"].tr.Send([]raft.Message{msg("a", "b", 1), msg("a", "c", 1)})
	waitFor(t, "b gets a's message", func() bool { return nodes["b"].rec.n() == 1 })
	waitFor(t, "c gets a's message", func() bool { return nodes["c"].rec.n() == 1 })

	// Node "a" holds a valid cert but claims to be "b": must be refused.
	aClient, _ := env.client(t, "a")
	post := func(body []byte) int {
		resp, err := aClient.Post(urls["c"]+Path, "application/octet-stream", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	before := nodes["c"].rec.n()
	if s := post(encode(t, header{wireVersion, "b", "c"}, []raft.Message{msg("b", "c", 9)})); s != 403 {
		t.Errorf("spoofed From over mTLS: status %d, want 403", s)
	}
	if nodes["c"].rec.n() != before {
		t.Error("spoofed message was delivered")
	}
	if s := post(encode(t, header{wireVersion, "a", "c"}, []raft.Message{msg("a", "c", 9)})); s != 204 {
		t.Errorf("honest message: status %d", s)
	}

	// Plain-HTTP handler (no TLS state) must refuse when identity is required.
	rr := rawPost(nodes["c"].tr.Handler(), "POST", encode(t, header{wireVersion, "a", "c"}, nil), nil)
	if rr.Code != 403 {
		t.Errorf("no TLS state: %d, want 403", rr.Code)
	}
}
