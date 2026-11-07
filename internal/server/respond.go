package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/tarnan3751/password-vault/internal/api"
	"github.com/tarnan3751/password-vault/internal/fsm"
)

// Request body limits (api.md §1).
const (
	maxBody      = 1 << 20
	maxRekeyBody = 32 << 20
	maxEmptyBody = 1 << 10
	// Unauthenticated endpoints get much smaller limits: they are reachable
	// by anyone, and legitimate bodies are tiny (a registration with every
	// field at its maximum is about 17 KiB).
	maxSmallBody    = 4 << 10 // prelogin, login
	maxRegisterBody = 32 << 10
)

// retryAfterUnavailable is what clients are told to wait after a 503.
const retryAfterUnavailableMs = 1000

// apiError is a failure response: an HTTP status plus api.ErrorDetail.
type apiError struct {
	status int
	detail api.ErrorDetail
}

func newAPIError(status int, code, msg string) *apiError {
	return &apiError{status: status, detail: api.ErrorDetail{Code: code, Message: msg}}
}

func errBadRequest(msg string) *apiError {
	return newAPIError(http.StatusBadRequest, api.CodeBadRequest, msg)
}
func errUnauthorized(msg string) *apiError {
	return newAPIError(http.StatusUnauthorized, api.CodeUnauthorized, msg)
}
func errForbidden(msg string) *apiError {
	return newAPIError(http.StatusForbidden, api.CodeForbidden, msg)
}
func errNotFound(msg string) *apiError {
	return newAPIError(http.StatusNotFound, api.CodeNotFound, msg)
}
func errTooLarge(msg string) *apiError {
	return newAPIError(http.StatusRequestEntityTooLarge, api.CodeTooLarge, msg)
}
func errInternal() *apiError {
	return newAPIError(http.StatusInternalServerError, api.CodeInternal, "internal error")
}
func errInvalidInvite() *apiError {
	return newAPIError(http.StatusForbidden, api.CodeInvalidInvite, "invite is unknown, used, revoked or expired")
}

func errUnavailable(msg string) *apiError {
	e := newAPIError(http.StatusServiceUnavailable, api.CodeUnavailable, msg)
	e.detail.RetryAfterMs = retryAfterUnavailableMs
	return e
}

func errOutcomeUnknown() *apiError {
	return newAPIError(http.StatusServiceUnavailable, api.CodeOutcomeUnknown,
		"the write was submitted but could not be confirmed; retry with the same Idempotency-Key")
}

func errRateLimited(waitMs int64) *apiError {
	if waitMs < 1 {
		waitMs = 1
	}
	e := newAPIError(http.StatusTooManyRequests, api.CodeRateLimited, "too many attempts; try again later")
	e.detail.RetryAfterMs = waitMs
	return e
}

var statusOfCode = map[string]int{
	api.CodeBadRequest:       http.StatusBadRequest,
	api.CodeUnauthorized:     http.StatusUnauthorized,
	api.CodeForbidden:        http.StatusForbidden,
	api.CodeNotFound:         http.StatusNotFound,
	api.CodeVersionConflict:  http.StatusConflict,
	api.CodeKeyEpochMismatch: http.StatusConflict,
	api.CodeAlreadyExists:    http.StatusConflict,
	api.CodeInvalidInvite:    http.StatusForbidden,
	api.CodeTooLarge:         http.StatusRequestEntityTooLarge,
	api.CodeLimitExceeded:    http.StatusUnprocessableEntity,
	api.CodeRateLimited:      http.StatusTooManyRequests,
	api.CodeUnavailable:      http.StatusServiceUnavailable,
	api.CodeOutcomeUnknown:   http.StatusServiceUnavailable,
	api.CodeInternal:         http.StatusInternalServerError,
}

// fromFSM maps a state-machine error to a response.
func fromFSM(e *fsm.Error) *apiError {
	st, ok := statusOfCode[e.Code]
	if !ok {
		return errInternal()
	}
	out := &apiError{status: st, detail: api.ErrorDetail{Code: e.Code, Message: e.Message, CurrentVersion: e.CurrentVersion}}
	if e.Code == api.CodeUnavailable {
		out.detail.RetryAfterMs = retryAfterUnavailableMs
	}
	return out
}

// jsonBufs recycles response buffers. A full sync is megabytes of base64;
// json.Marshal grew a fresh buffer for it, copied the result out, and adding
// the newline copied it once more.
var jsonBufs = sync.Pool{New: func() any { return new(bytes.Buffer) }}

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf := jsonBufs.Get().(*bytes.Buffer)
	defer jsonBufs.Put(buf)
	buf.Reset()
	if err := json.NewEncoder(buf).Encode(v); err != nil { // the same bytes as Marshal, plus a newline
		status = http.StatusInternalServerError
		buf.Reset()
		buf.WriteString(`{"error":{"code":"internal","message":"cannot encode response"}}` + "\n")
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) fail(w http.ResponseWriter, e *apiError) {
	h := w.Header()
	if e.detail.RetryAfterMs > 0 {
		h.Set("Retry-After", strconv.FormatInt((e.detail.RetryAfterMs+999)/1000, 10))
	}
	if e.status == http.StatusUnauthorized {
		h.Set("WWW-Authenticate", `Bearer realm="family-vault"`)
	}
	writeJSON(w, e.status, api.ErrorBody{Error: e.detail})
}

func isJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "application/json"
}

// decodeBody strictly decodes a JSON request body: application/json only
// (which also forces browsers to preflight cross-origin requests), at most
// limit bytes, no unknown fields, no trailing data.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any, limit int64) *apiError {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return errBadRequest("Content-Type must be application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return jsonError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errTooLarge("request body too large")
		}
		return errBadRequest("unexpected data after the JSON body")
	}
	return nil
}

// decodeEmpty accepts an empty body or an empty JSON object, for endpoints
// that take no input.
func decodeEmpty(w http.ResponseWriter, r *http.Request) *apiError {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEmptyBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return errTooLarge("request body too large")
		}
		return errBadRequest("cannot read request body")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return decodeBody(w, r, &struct{}{}, maxEmptyBody)
}

// jsonError turns a decoding error into a client error. The messages never
// echo input values (only field names), so nothing secret can be reflected.
func jsonError(err error) *apiError {
	var mbe *http.MaxBytesError
	var te *json.UnmarshalTypeError
	var se *json.SyntaxError
	switch {
	case errors.As(err, &mbe):
		return errTooLarge("request body too large")
	case errors.Is(err, io.EOF):
		return errBadRequest("request body is empty")
	case errors.As(err, &te):
		return errBadRequest("invalid value for field " + strconv.Quote(te.Field))
	case errors.As(err, &se):
		return errBadRequest("malformed JSON at offset " + strconv.FormatInt(se.Offset, 10))
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		return errBadRequest(err.Error())
	}
	return errBadRequest("malformed JSON body")
}
