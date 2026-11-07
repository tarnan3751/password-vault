package chaos

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"

	"github.com/tarnan3751/password-vault/internal/api"
)

// callResult is the outcome of ONE HTTP attempt.
type callResult struct {
	Status int
	Err    *api.ErrorDetail // non-2xx body
	Body   []byte           // 2xx body
	// NetErr is set when no HTTP response was received.
	NetErr error
	// NotSent: no attempt ever finished writing the request, so the server
	// cannot have acted on it. Every other network error leaves the
	// outcome open.
	NotSent bool
}

func (r callResult) ok() bool { return r.NetErr == nil && r.Status/100 == 2 }

func (r callResult) code() string {
	if r.Err != nil {
		return r.Err.Code
	}
	return ""
}

// short is a compact description for attempt logs.
func (r callResult) short() string {
	switch {
	case r.NetErr != nil && r.NotSent:
		return "notsent: " + trimErr(r.NetErr)
	case r.NetErr != nil:
		return "neterr: " + trimErr(r.NetErr)
	case r.ok():
		return fmt.Sprint(r.Status)
	case r.Err != nil:
		return fmt.Sprintf("%d %s", r.Status, r.Err.Code)
	}
	return fmt.Sprint(r.Status)
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}

// maybeApplied reports whether a write attempt with this result might have
// taken effect even though it did not report success.
func (r callResult) maybeApplied() bool {
	if r.NetErr != nil {
		return !r.NotSent
	}
	if r.Status/100 == 2 {
		return true
	}
	switch r.code() {
	case api.CodeOutcomeUnknown, api.CodeInternal:
		return true
	}
	// 503 unavailable: "nothing was changed" (api.md §1). Other 4xx/5xx
	// are definite results recorded by the state machine or rejections
	// before proposing.
	return r.Status >= 500 && r.code() != api.CodeUnavailable
}

// apiCall performs one request. body may be nil. A request whose
// connection could not be dialled is flagged NotSent.
func apiCall(ctx context.Context, hc *http.Client, method, url, token, idemKey string, body any) callResult {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return callResult{NetErr: err, NotSent: true}
		}
		rd = bytes.NewReader(b)
	}
	// Whether the request may have reached the server is decided by
	// tracing, not by the error's type. net/http treats a request carrying
	// an Idempotency-Key as replayable and silently re-sends it on a new
	// connection when a reused keep-alive connection dies after the
	// request was written; against a killed node that hidden retry then
	// fails to DIAL, and the error we see is a dial error although the
	// first copy may have been applied. WroteRequest fires for every
	// internal attempt (HTTP/1.1 and HTTP/2) and reports Err == nil only
	// when the complete request was written; a partial request cannot be
	// acted on, so "never completely written" is exactly "not sent".
	var wrote atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				wrote.Store(true)
			}
		},
	})
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return callResult{NetErr: err, NotSent: true}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return callResult{NetErr: err, NotSent: !wrote.Load()}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		// Headers arrived, so the server handled the request; only the
		// body is lost. For a write the outcome is therefore open.
		return callResult{NetErr: fmt.Errorf("reading %d response: %w", resp.StatusCode, err)}
	}
	r := callResult{Status: resp.StatusCode}
	if resp.StatusCode/100 == 2 {
		r.Body = data
		return r
	}
	var eb api.ErrorBody
	if json.Unmarshal(data, &eb) == nil && eb.Error.Code != "" {
		r.Err = &eb.Error
	} else {
		r.Err = &api.ErrorDetail{Code: fmt.Sprintf("http_%d", resp.StatusCode), Message: strings.TrimSpace(string(data))}
	}
	return r
}

func decodeInto(r callResult, out any) error {
	if !r.ok() {
		return fmt.Errorf("not a success: %s", r.short())
	}
	return json.Unmarshal(r.Body, out)
}
