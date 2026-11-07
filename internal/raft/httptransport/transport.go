// Package httptransport implements raft.Transport over HTTP(S).
//
// Wire format: POST <peer base URL>/raft/msgs with Content-Type
// application/octet-stream. The body is a single gob stream holding two
// values in order: a header (struct {Version int; From, To string}) and a
// []raft.Message. Responses carry no payload (204 on success); Raft's own
// replies travel as separate messages in the opposite direction.
package httptransport

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tarnan3751/password-vault/internal/raft"
	"github.com/tarnan3751/password-vault/internal/tlsutil"
)

// Path is the URL path served by Handler and POSTed to on peers.
const Path = "/raft/msgs"

// wireVersion is bumped on incompatible header/body changes.
const wireVersion = 1

const (
	defaultQueueSize      = 256
	defaultMaxBatchBytes  = 4 << 20
	defaultMaxBodyBytes   = 128 << 20
	defaultRequestTimeout = 5 * time.Second
	minBackoff            = 50 * time.Millisecond
	maxBackoff            = time.Second
)

// header precedes the messages in every request body.
type header struct {
	Version int
	From    string
	To      string
}

// Options configures a Transport; see field comments for defaults.
type Options struct {
	LocalID string
	// Peers maps peer node ID to base URL. An entry for LocalID is ignored.
	Peers map[string]string
	// Client sends outbound requests; the caller configures (m)TLS on it.
	// nil selects a client with keep-alive and no TLS customization.
	Client *http.Client
	// QueueSize is the per-peer outbound queue length in messages (256).
	QueueSize int
	// MaxBatchBytes is a soft cap on one POST body (4 MiB). A single larger
	// message is still sent alone.
	MaxBatchBytes int
	// MaxBodyBytes limits inbound bodies (128 MiB).
	MaxBodyBytes int64
	// RequestTimeout is the base per-request timeout (5s); 1s per MiB of
	// body is added so snapshots can complete.
	RequestTimeout time.Duration
	// RequireTLSIdentity demands a verified client certificate whose Subject
	// CN equals the sending node's ID.
	RequireTLSIdentity bool
	Logger             *slog.Logger
}

// PeerStats are cumulative per-peer counters, counted in messages.
type PeerStats struct {
	Sent    uint64 // delivered (peer answered 2xx)
	Dropped uint64 // discarded: queue overflow, or Send after Close
	Failed  uint64 // lost in a failed POST
}

type peer struct {
	id  string
	url string

	mu sync.Mutex
	q  []raft.Message

	wake chan struct{} // capacity 1; signals "queue non-empty"

	sent, dropped, failed atomic.Uint64
}

// Transport implements raft.Transport.
type Transport struct {
	opts   Options
	log    *slog.Logger
	client *http.Client
	peers  map[string]*peer

	handler atomic.Pointer[func(raft.Message)]

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
	wg     sync.WaitGroup
	once   sync.Once
}

var _ raft.Transport = (*Transport)(nil)

// New validates opts and starts one sender goroutine per peer.
func New(opts Options) (*Transport, error) {
	if opts.LocalID == "" {
		return nil, errors.New("httptransport: LocalID is required")
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.MaxBatchBytes <= 0 {
		opts.MaxBatchBytes = defaultMaxBatchBytes
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = defaultMaxBodyBytes
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = defaultRequestTimeout
	}
	log := opts.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	client := opts.Client
	if client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConnsPerHost = 2
		client = &http.Client{Transport: tr}
	}
	t := &Transport{opts: opts, log: log, client: client, peers: map[string]*peer{}}
	t.ctx, t.cancel = context.WithCancel(context.Background())
	for id, base := range opts.Peers {
		if id == opts.LocalID {
			continue
		}
		if id == "" || base == "" {
			t.cancel()
			return nil, fmt.Errorf("httptransport: invalid peer entry %q -> %q", id, base)
		}
		t.peers[id] = &peer{
			id:   id,
			url:  strings.TrimRight(base, "/") + Path,
			wake: make(chan struct{}, 1),
		}
	}
	for _, p := range t.peers {
		t.wg.Add(1)
		go t.sender(p)
	}
	return t, nil
}

// SetHandler installs the inbound message callback. It may be called
// concurrently with inbound traffic; until set, inbound requests get 503 so
// the sender counts them as failed rather than silently losing them.
func (t *Transport) SetHandler(h func(raft.Message)) {
	if h == nil {
		t.handler.Store(nil)
		return
	}
	t.handler.Store(&h)
}

// Send enqueues msgs per destination and never blocks on the network.
func (t *Transport) Send(msgs []raft.Message) {
	touched := map[*peer]struct{}{}
	for _, m := range msgs {
		p := t.peers[m.To] // unknown peers and self are not in the map
		if p == nil {
			continue
		}
		if t.closed.Load() {
			p.dropped.Add(1)
			continue
		}
		p.mu.Lock()
		if len(p.q) >= t.opts.QueueSize {
			// Drop OLDEST. Raft retransmits everything, and the newest
			// messages (heartbeats, votes, current-term appends) are the
			// ones that still matter; a backlog of stale appends to a slow
			// peer is worth less than the fresh message replacing it.
			copy(p.q, p.q[1:])
			p.q[len(p.q)-1] = m
			p.dropped.Add(1)
		} else {
			p.q = append(p.q, m)
		}
		p.mu.Unlock()
		touched[p] = struct{}{}
	}
	for p := range touched {
		select {
		case p.wake <- struct{}{}:
		default:
		}
	}
}

// Stats returns a snapshot of per-peer counters.
func (t *Transport) Stats() map[string]PeerStats {
	out := make(map[string]PeerStats, len(t.peers))
	for id, p := range t.peers {
		out[id] = PeerStats{Sent: p.sent.Load(), Dropped: p.dropped.Load(), Failed: p.failed.Load()}
	}
	return out
}

// Close stops senders, drops queued messages and makes Handler answer 503.
// It is idempotent.
func (t *Transport) Close() error {
	t.once.Do(func() {
		t.closed.Store(true)
		t.cancel()
		t.wg.Wait()
		for _, p := range t.peers {
			p.mu.Lock()
			p.dropped.Add(uint64(len(p.q)))
			p.q = nil
			p.mu.Unlock()
		}
		t.client.CloseIdleConnections()
	})
	return nil
}

// estimate cheaply approximates the encoded size of m without encoding it.
func estimate(m *raft.Message) int {
	n := 192 + len(m.Data) + len(m.Error) + len(m.From) + len(m.To)
	for i := range m.Entries {
		n += 32 + len(m.Entries[i].Data)
	}
	if m.Snap != nil {
		n += 32 + len(m.Snap.Data)
	}
	return n
}

// take removes up to MaxBatchBytes worth of messages (at least one).
func (t *Transport) take(p *peer) []raft.Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	n, size := 0, 0
	for n < len(p.q) {
		s := estimate(&p.q[n])
		if n > 0 && size+s > t.opts.MaxBatchBytes {
			break
		}
		size += s
		n++
	}
	if n == 0 {
		return nil
	}
	batch := make([]raft.Message, n)
	copy(batch, p.q[:n])
	rest := copy(p.q, p.q[n:])
	for i := rest; i < len(p.q); i++ {
		p.q[i] = raft.Message{} // release payloads
	}
	p.q = p.q[:rest]
	return batch
}

// sender is the only goroutine posting to p, which keeps per-peer ordering
// (a single request in flight) without any extra locking.
func (t *Transport) sender(p *peer) {
	defer t.wg.Done()
	backoff := time.Duration(0)
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-p.wake:
		}
		for {
			batch := t.take(p)
			if len(batch) == 0 {
				break
			}
			if err := t.post(p, batch); err != nil {
				if t.ctx.Err() != nil {
					p.dropped.Add(uint64(len(batch)))
					return
				}
				// No retry: Raft resends what still matters. Backing off
				// bounds the cost of a dead peer; messages arriving in the
				// meantime pile up only to QueueSize (oldest dropped).
				p.failed.Add(uint64(len(batch)))
				if backoff == 0 {
					backoff = minBackoff
				} else if backoff *= 2; backoff > maxBackoff {
					backoff = maxBackoff
				}
				t.log.Debug("raft send failed", "peer", p.id, "err", err, "backoff", backoff)
				select {
				case <-time.After(backoff):
				case <-t.ctx.Done():
					return
				}
				continue
			}
			backoff = 0
			p.sent.Add(uint64(len(batch)))
		}
	}
}

func (t *Transport) post(p *peer, batch []raft.Message) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(header{Version: wireVersion, From: t.opts.LocalID, To: p.id}); err != nil {
		return err
	}
	if err := enc.Encode(batch); err != nil {
		return err
	}
	timeout := t.opts.RequestTimeout + time.Duration(buf.Len()>>20)*time.Second
	ctx, cancel := context.WithTimeout(t.ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(buf.Bytes()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	// Drain (bounded) so the connection can be reused.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("peer %s: status %d", p.id, resp.StatusCode)
	}
	return nil
}

// Handler serves POST /raft/msgs. Mount it on the peer listener.
func (t *Transport) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(Path, t.serve)
	return mux
}

func (t *Transport) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if t.closed.Load() {
		http.Error(w, "closed", http.StatusServiceUnavailable)
		return
	}
	hp := t.handler.Load()
	if hp == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	certID := ""
	if t.opts.RequireTLSIdentity {
		id, err := tlsutil.PeerNodeID(r.TLS)
		if err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		certID = id
	}

	body := http.MaxBytesReader(w, r.Body, t.opts.MaxBodyBytes)
	msgs, hdr, status := t.decode(body)
	if status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	if hdr.To != t.opts.LocalID {
		http.Error(w, "wrong recipient", http.StatusBadRequest)
		return
	}
	if _, ok := t.peers[hdr.From]; !ok {
		http.Error(w, "unknown sender", http.StatusForbidden)
		return
	}
	if t.opts.RequireTLSIdentity && certID != hdr.From {
		http.Error(w, "certificate does not match sender", http.StatusForbidden)
		return
	}
	// Validate everything before delivering anything: a partly-accepted
	// batch from a confused or hostile sender is worse than none.
	for i := range msgs {
		if msgs[i].From != hdr.From || msgs[i].To != t.opts.LocalID {
			http.Error(w, "message addressing mismatch", http.StatusForbidden)
			return
		}
	}
	h := *hp
	for _, m := range msgs {
		h(m)
	}
	w.WriteHeader(http.StatusNoContent)
}

// decode parses the body; a non-zero status means rejection. gob reads only
// from the size-limited reader, so decoding is bounded by MaxBodyBytes.
func (t *Transport) decode(body io.Reader) (msgs []raft.Message, hdr header, status int) {
	defer func() {
		if r := recover(); r != nil { // hostile input must never crash the node
			msgs, hdr, status = nil, header{}, http.StatusBadRequest
		}
	}()
	fail := func(err error) int {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusBadRequest
	}
	dec := gob.NewDecoder(body)
	if err := dec.Decode(&hdr); err != nil {
		return nil, hdr, fail(err)
	}
	if hdr.Version != wireVersion {
		return nil, hdr, http.StatusBadRequest
	}
	if err := dec.Decode(&msgs); err != nil {
		return nil, hdr, fail(err)
	}
	return msgs, hdr, 0
}
