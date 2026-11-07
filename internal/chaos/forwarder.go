package chaos

import (
	"io"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Forwarder is a TCP relay that sits on one DIRECTED peer link of the
// process-mode cluster: node i's config names the forwarder's port as node
// j's peer_addr, so every HTTP request i sends to j (the carrier of i -> j
// Raft messages) passes through it, and nothing else does. TLS passes
// through untouched; the handshake and node-identity checks happen end to
// end between the two vaultd processes.
//
// Modes:
//   - normal: bytes are relayed (optionally delayed per chunk, and with
//     probability Drop a chunk resets both connections, which is how a
//     lossy link looks to TCP-based HTTP);
//   - cut: every existing connection is closed and new ones are accepted
//     and closed immediately (the dialer sees a reset/EOF);
//   - blackhole: connections are accepted but bytes stop moving in both
//     directions until the mode changes, like a route that silently drops
//     packets. When the link heals, stalled bytes resume: requests that the
//     sender has long since given up on may then arrive late, which Raft
//     must tolerate.
type Forwarder struct {
	ln     net.Listener
	target string

	mu    sync.Mutex
	cond  *sync.Cond
	fault LinkFault
	conns map[*fwdPair]struct{}
	rng   *rand.Rand
	gen   uint64 // bumped on every cut, so pumps notice they must die

	closed atomic.Bool
	wg     sync.WaitGroup
}

type fwdPair struct {
	client, server net.Conn
	gen            uint64
	once           sync.Once
}

func (p *fwdPair) close() {
	p.once.Do(func() {
		p.client.Close()
		if p.server != nil {
			p.server.Close()
		}
	})
}

// NewForwarder listens on a fresh loopback port and relays to target.
func NewForwarder(target string, seed int64) (*Forwarder, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &Forwarder{ln: ln, target: target, conns: map[*fwdPair]struct{}{},
		rng: rand.New(rand.NewPCG(uint64(seed), 0xf0f0))}
	f.cond = sync.NewCond(&f.mu)
	f.wg.Add(1)
	go f.acceptLoop()
	return f, nil
}

// Addr is the address peers dial.
func (f *Forwarder) Addr() string { return f.ln.Addr().String() }

// Set changes the link's behaviour. Cutting closes every live connection.
func (f *Forwarder) Set(fault LinkFault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = fault
	if fault.Cut {
		f.gen++
		for p := range f.conns {
			p.close()
			delete(f.conns, p)
		}
	}
	f.cond.Broadcast()
}

// Close stops the forwarder and every connection through it.
func (f *Forwarder) Close() {
	if f.closed.Swap(true) {
		return
	}
	f.ln.Close()
	f.mu.Lock()
	for p := range f.conns {
		p.close()
	}
	f.conns = map[*fwdPair]struct{}{}
	f.cond.Broadcast()
	f.mu.Unlock()
	f.wg.Wait()
}

func (f *Forwarder) acceptLoop() {
	defer f.wg.Done()
	for {
		c, err := f.ln.Accept()
		if err != nil {
			if f.closed.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		f.wg.Add(1)
		go f.handle(c)
	}
}

// waitPassable blocks while the link is blackholed. It returns false if the
// connection must be dropped instead (cut, closed, or a cut happened since
// the connection was created).
func (f *Forwarder) waitPassable(gen uint64) (LinkFault, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		if f.closed.Load() || f.fault.Cut || f.gen != gen {
			return f.fault, false
		}
		if !f.fault.Blackhole {
			return f.fault, true
		}
		f.cond.Wait()
	}
}

func (f *Forwarder) handle(c net.Conn) {
	defer f.wg.Done()
	f.mu.Lock()
	gen := f.gen
	if f.fault.Cut || f.closed.Load() {
		f.mu.Unlock()
		c.Close()
		return
	}
	p := &fwdPair{client: c, gen: gen}
	f.conns[p] = struct{}{}
	f.mu.Unlock()
	defer func() {
		p.close()
		f.mu.Lock()
		delete(f.conns, p)
		f.mu.Unlock()
	}()
	// A blackholed link accepts the connection but never reaches the
	// other side until it heals.
	if _, ok := f.waitPassable(gen); !ok {
		return
	}
	s, err := net.DialTimeout("tcp", f.target, 3*time.Second)
	if err != nil {
		return
	}
	f.mu.Lock()
	if f.gen != gen || f.closed.Load() {
		f.mu.Unlock()
		s.Close()
		return
	}
	p.server = s
	f.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() { f.pump(p, c, s); done <- struct{}{} }()
	go func() { f.pump(p, s, c); done <- struct{}{} }()
	<-done
	p.close()
	<-done
}

func (f *Forwarder) pump(p *fwdPair, src, dst net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			fault, ok := f.waitPassable(p.gen)
			if !ok {
				return
			}
			if fault.Drop > 0 {
				f.mu.Lock()
				reset := f.rng.Float64() < fault.Drop
				f.mu.Unlock()
				if reset {
					return
				}
			}
			var d time.Duration
			if fault.DelayMax > 0 {
				f.mu.Lock()
				d = fault.delay(f.rng)
				f.mu.Unlock()
			}
			if d > 0 {
				time.Sleep(d)
				if _, ok := f.waitPassable(p.gen); !ok {
					return
				}
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if err == io.EOF {
				// Half-close so the other direction can finish.
				if tc, ok := dst.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
					return
				}
			}
			return
		}
	}
}
