package chaos

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// TestApiCallNotSentClassification reproduces a node dying after it read a
// write: net/http retries the (replayable, because of the Idempotency-Key)
// request on a fresh connection, the dial fails, and the error looks like
// "never sent". The harness must still say the write may have been
// applied, or it would wrongly record the operation as certainly failed.
func TestApiCallNotSentClassification(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	var calls atomic.Int32
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusNoContent) // warms a keep-alive connection
			return
		}
		// The "node" has read the whole request and dies before answering:
		// stop accepting, then drop the connection.
		ln.Close()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()
	hc := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r := apiCall(ctx, hc, http.MethodPut, "http://"+addr+"/x", "", "0123456789abcdef0123456789abcdef", map[string]int{"a": 1}); !r.ok() {
		t.Fatalf("warm-up: %s", r.short())
	}
	r := apiCall(ctx, hc, http.MethodPut, "http://"+addr+"/x", "", "0123456789abcdef0123456789abcdef", map[string]int{"a": 2})
	if r.NetErr == nil {
		t.Fatalf("expected a network error, got %s", r.short())
	}
	if r.NotSent {
		t.Fatalf("a request the server had read was classified as never sent: %v", r.NetErr)
	}
	if !r.maybeApplied() {
		t.Fatal("not maybeApplied")
	}
	// Against a closed port nothing is ever written: certainly not sent.
	r = apiCall(ctx, hc, http.MethodPut, "http://"+addr+"/x", "", "0123456789abcdef0123456789abcdef", map[string]int{"a": 3})
	if r.NetErr == nil || !r.NotSent || r.maybeApplied() {
		t.Fatalf("dead port: NotSent=%v err=%v", r.NotSent, r.NetErr)
	}
}
