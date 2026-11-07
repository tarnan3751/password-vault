package chaos

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/raft/httptransport"
)

// fakeTransport records what the decorator passes on and lets the test
// inject inbound messages.
type fakeTransport struct {
	mu      sync.Mutex
	sent    []raft.Message
	handler func(raft.Message)
	closed  bool
}

func (f *fakeTransport) Send(msgs []raft.Message) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msgs...)
}
func (f *fakeTransport) SetHandler(h func(raft.Message)) { f.handler = h }
func (f *fakeTransport) Close() error                    { f.closed = true; return nil }
func (f *fakeTransport) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sent)
}

func msgs(from, to string, n int) []raft.Message {
	out := make([]raft.Message, n)
	for i := range out {
		out[i] = raft.Message{Type: raft.MsgApp, From: from, To: to, Index: uint64(i)}
	}
	return out
}

func TestFaultTransportCutsBothSides(t *testing.T) {
	net := NewFaultNet(1)
	inner := &fakeTransport{}
	ft := net.Wrap("a", inner)
	var got []raft.Message
	ft.SetHandler(func(m raft.Message) { got = append(got, m) })

	ft.Send(msgs("a", "b", 3))
	if inner.count() != 3 {
		t.Fatalf("healthy link passed %d of 3", inner.count())
	}
	net.Set("a", "b", LinkFault{Cut: true})
	ft.Send(msgs("a", "b", 3))
	ft.Send(msgs("a", "c", 2)) // other links unaffected
	if inner.count() != 5 {
		t.Fatalf("cut a->b: inner got %d, want 5", inner.count())
	}
	// The receive side: a batch from b that was already in flight when b->a
	// was cut is discarded on arrival.
	inner.handler(raft.Message{From: "b", To: "a"})
	net.Set("b", "a", LinkFault{Cut: true})
	inner.handler(raft.Message{From: "b", To: "a"})
	inner.handler(raft.Message{From: "c", To: "a"})
	if len(got) != 2 {
		t.Fatalf("handler got %d messages, want 2 (one before the cut, one from c)", len(got))
	}
	// One-way: a->b healed, b->a still cut.
	net.Set("a", "b", LinkFault{})
	ft.Send(msgs("a", "b", 1))
	if inner.count() != 6 {
		t.Fatalf("after uncut: %d", inner.count())
	}
	inner.handler(raft.Message{From: "b", To: "a"})
	if len(got) != 2 {
		t.Fatal("one-way cut b->a leaked a message")
	}
	net.Heal()
	inner.handler(raft.Message{From: "b", To: "a"})
	if len(got) != 3 {
		t.Fatal("heal did not restore b->a")
	}
	s := net.Stats()
	if s.CutOnSend != 3 || s.CutOnReceive != 2 {
		t.Fatalf("stats %+v", s)
	}
}

func TestFaultTransportLossDupDelay(t *testing.T) {
	net := NewFaultNet(42)
	inner := &fakeTransport{}
	ft := net.Wrap("a", inner)
	net.Set("a", "b", LinkFault{Drop: 0.3})
	ft.Send(msgs("a", "b", 2000))
	if n := inner.count(); n < 1250 || n > 1550 {
		t.Fatalf("30%% loss passed %d of 2000", n)
	}
	inner.sent = nil
	net.Set("a", "b", LinkFault{Dup: 0.5})
	ft.Send(msgs("a", "b", 1000))
	if n := inner.count(); n < 1400 || n > 1600 {
		t.Fatalf("50%% duplication delivered %d for 1000", n)
	}
	inner.sent = nil
	net.Set("a", "b", LinkFault{DelayMin: 40 * time.Millisecond, DelayMax: 60 * time.Millisecond})
	m := msgs("a", "b", 1)
	m[0].Entries = []raft.Entry{{Index: 1, Data: []byte("x")}}
	ft.Send(m)
	m[0].Entries[0].Data[0] = 'y' // the core may reuse its buffers after Send
	if inner.count() != 0 {
		t.Fatal("delayed message delivered immediately")
	}
	time.Sleep(100 * time.Millisecond)
	if inner.count() != 1 || string(inner.sent[0].Entries[0].Data) != "x" {
		t.Fatalf("delayed message: %d delivered, content %+v", inner.count(), inner.sent)
	}
	// A partition installed while a delayed message is in flight eats it.
	inner.sent = nil
	ft.Send(msgs("a", "b", 1))
	net.Set("a", "b", LinkFault{Cut: true})
	time.Sleep(100 * time.Millisecond)
	if inner.count() != 0 {
		t.Fatal("a cut did not eat a delayed message")
	}
	// Close stops delayed deliveries too.
	net.Set("a", "b", LinkFault{DelayMin: 20 * time.Millisecond, DelayMax: 20 * time.Millisecond})
	ft.Send(msgs("a", "b", 1))
	ft.Close()
	time.Sleep(60 * time.Millisecond)
	if inner.count() != 0 || !inner.closed {
		t.Fatal("closed transport delivered or did not close inner")
	}
}

// TestFaultTransportOverHTTP runs the decorator on the real HTTP transport
// over loopback, as the in-process cluster does.
func TestFaultTransportOverHTTP(t *testing.T) {
	net := NewFaultNet(3)
	recv := map[string]chan raft.Message{"a": make(chan raft.Message, 100), "b": make(chan raft.Message, 100)}
	lns := map[string]net0{}
	for _, id := range []string{"a", "b"} {
		lns[id] = listen(t)
	}
	fts := map[string]*FaultTransport{}
	for _, id := range []string{"a", "b"} {
		peers := map[string]string{}
		for _, o := range []string{"a", "b"} {
			if o != id {
				peers[o] = "http://" + lns[o].addr
			}
		}
		ht, err := httptransport.New(httptransport.Options{LocalID: id, Peers: peers})
		if err != nil {
			t.Fatal(err)
		}
		srv := &http.Server{Handler: ht.Handler()}
		go srv.Serve(lns[id].ln)
		t.Cleanup(func() { srv.Close() })
		ft := net.Wrap(id, ht)
		ch := recv[id]
		ft.SetHandler(func(m raft.Message) { ch <- m })
		t.Cleanup(func() { ft.Close() })
		fts[id] = ft
	}
	expect := func(id string, want bool) {
		t.Helper()
		select {
		case <-recv[id]:
			if !want {
				t.Fatalf("%s received a message across a cut", id)
			}
		case <-time.After(500 * time.Millisecond):
			if want {
				t.Fatalf("%s did not receive", id)
			}
		}
	}
	fts["a"].Send(msgs("a", "b", 1))
	expect("b", true)
	net.Set("a", "b", LinkFault{Cut: true})
	fts["a"].Send(msgs("a", "b", 1))
	expect("b", false)
	fts["b"].Send(msgs("b", "a", 1)) // the other direction still works
	expect("a", true)
	net.Heal()
	fts["a"].Send(msgs("a", "b", 1))
	expect("b", true)
}

type net0 struct {
	ln   net.Listener
	addr string
}

func listen(t *testing.T) net0 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return net0{ln, ln.Addr().String()}
}

// TestForwarder checks the TCP relay used between vaultd processes.
func TestForwarder(t *testing.T) {
	echo := listen(t)
	go func() {
		for {
			c, err := echo.ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	t.Cleanup(func() { echo.ln.Close() })
	f, err := NewForwarder(echo.addr, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.Close)

	roundTrip := func(c net.Conn, msg string, timeout time.Duration) error {
		c.SetDeadline(time.Now().Add(timeout))
		if _, err := c.Write([]byte(msg + "\n")); err != nil {
			return err
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err == nil && line != msg+"\n" {
			t.Fatalf("echo %q", line)
		}
		return err
	}
	c, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(c, "hello", time.Second); err != nil {
		t.Fatalf("normal: %v", err)
	}
	// Delay.
	f.Set(LinkFault{DelayMin: 100 * time.Millisecond, DelayMax: 100 * time.Millisecond})
	start := time.Now()
	if err := roundTrip(c, "slow", 2*time.Second); err != nil || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("delay: err %v after %v", err, time.Since(start))
	}
	// Blackhole: bytes stall, then resume after the heal.
	f.Set(LinkFault{Blackhole: true})
	if err := roundTrip(c, "stalled", 300*time.Millisecond); err == nil {
		t.Fatal("blackhole let bytes through")
	}
	f.Set(LinkFault{})
	c.SetDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "stalled\n" {
		t.Fatalf("after blackhole heal: %q %v", line, err)
	}
	// Cut: the live connection dies and new ones are refused.
	f.Set(LinkFault{Cut: true})
	if err := roundTrip(c, "cut", time.Second); err == nil {
		t.Fatal("cut connection still works")
	}
	c2, err := net.Dial("tcp", f.Addr())
	if err == nil {
		if err := roundTrip(c2, "x", 500*time.Millisecond); err == nil {
			t.Fatal("new connection through a cut link works")
		}
		c2.Close()
	}
	f.Set(LinkFault{})
	c3, err := net.Dial("tcp", f.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(c3, "healed", time.Second); err != nil {
		t.Fatalf("after heal: %v", err)
	}
	c3.Close()
}

func TestParseFaults(t *testing.T) {
	inproc := Caps{Loss: true, Dup: true, Delay: true}
	all, err := ParseFaults("all", inproc)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range all {
		if k == FPause || k == FPauseLeader || k == FPausePartition {
			t.Fatalf("in-process schedule contains %s", k)
		}
	}
	got, err := ParseFaults("kill,-kill-majority,bridge", inproc)
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v %v", got, err)
	}
	if _, err := ParseFaults("pause", inproc); err != nil {
		t.Fatalf("a group silently drops unsupported kinds: %v", err)
	}
	if _, err := ParseFaults("pause-leader", inproc); err == nil {
		t.Fatal("explicit unsupported kind accepted")
	}
	if _, err := ParseFaults("bogus", inproc); err == nil {
		t.Fatal("unknown kind accepted")
	}
}
