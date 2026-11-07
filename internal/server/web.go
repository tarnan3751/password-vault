package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// permissionsPolicy disables browser features the vault UI never uses, so
// that even injected script could not reach them. Clipboard access is left
// at its default (the UI copies passwords).
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), " +
	"fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), " +
	"midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), " +
	"usb=(), xr-spatial-tracking=()"

// securityHeaders is applied to every response, API and static alike.
func (s *Server) securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", s.csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Permissions-Policy", permissionsPolicy)
	h.Set("X-Frame-Options", "DENY")
	if r.TLS != nil {
		h.Set("Strict-Transport-Security", "max-age=63072000")
	}
}

var staticTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".mjs":         "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".webmanifest": "application/manifest+json",
	".wasm":        "application/wasm",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".woff2":       "font/woff2",
	".txt":         "text/plain; charset=utf-8",
	".map":         "application/json",
}

func contentType(name string) string {
	ext := strings.ToLower(path.Ext(name))
	if t, ok := staticTypes[ext]; ok {
		return t
	}
	if t := mime.TypeByExtension(ext); t != "" {
		return t
	}
	return "application/octet-stream"
}

const placeholderPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Family Vault</title></head>
<body><h1>Family Vault</h1><p>This node is running. The web client is not included in this build.</p></body></html>
`

// staticFile is one file of the web client, prepared on first use: the
// bytes, a gzip encoding when that is smaller, and an entity tag for each.
// On a Raspberry Pi's home uplink the app shell is the slowest thing a new
// device fetches; compressed it is about a third of the size, and with the
// tags a revalidation is answered with 304 instead of the whole file.
type staticFile struct {
	data, gz     []byte // gz is nil if compressing does not pay
	etag, gzETag string
	ctype, cache string
}

func newStaticFile(name string, data []byte) *staticFile {
	sum := sha256.Sum256(data)
	tag := hex.EncodeToString(sum[:16])
	f := &staticFile{data: data, etag: `"` + tag + `"`, gzETag: `"` + tag + `-gzip"`, ctype: contentType(name)}
	switch {
	case name == "index.html" || name == "sw.js":
		// Always revalidate the entry points so a new release takes effect.
		f.cache = "no-cache"
	case strings.HasPrefix(name, "assets/"):
		// web/scripts/build.mjs names everything under assets/ by its
		// content hash, so a name never refers to other bytes.
		f.cache = "public, max-age=31536000, immutable"
	default:
		f.cache = "public, max-age=3600"
	}
	var b bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression) // the level is valid
	_, _ = zw.Write(data)                                  // writes to a bytes.Buffer cannot fail
	if zw.Close() == nil && b.Len() < len(data)-len(data)/10 {
		f.gz = b.Bytes()
	}
	return f
}

// static returns the prepared file name of WebFS. Only files that exist
// are cached, so the cache is bounded by the embedded client.
func (s *Server) static(name string) (*staticFile, bool) {
	s.webMu.Lock()
	defer s.webMu.Unlock()
	if f, ok := s.webFiles[name]; ok {
		return f, true
	}
	if !fs.ValidPath(name) {
		return nil, false
	}
	if st, err := fs.Stat(s.cfg.WebFS, name); err != nil || st.IsDir() {
		return nil, false
	}
	data, err := fs.ReadFile(s.cfg.WebFS, name)
	if err != nil {
		return nil, false
	}
	f := newStaticFile(name, data)
	s.webFiles[name] = f
	return f, true
}

// serveStatic serves the embedded single-page app. Unknown paths fall back
// to index.html so that client-side routes survive a reload. API responses
// are never compressed (they mix secret-derived data with input an attacker
// may influence, and ciphertext does not compress anyway); only these
// static files are.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.WebFS == nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(placeholderPage))
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	f, ok := s.static(name)
	if !ok {
		if f, ok = s.static("index.html"); !ok {
			http.NotFound(w, r)
			return
		}
	}
	h := w.Header()
	h.Set("Content-Type", f.ctype)
	h.Set("Cache-Control", f.cache)
	body, etag := f.data, f.etag
	if f.gz != nil {
		h.Add("Vary", "Accept-Encoding")
		if acceptsGzip(r) {
			body, etag = f.gz, f.gzETag
			h.Set("Content-Encoding", "gzip")
			// ServeContent leaves the length unset when an encoding is set.
			h.Set("Content-Length", strconv.Itoa(len(body)))
		}
	}
	// ServeContent answers If-None-Match (304), ranges and HEAD.
	h.Set("ETag", etag)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

// acceptsGzip reports whether the request's Accept-Encoding allows gzip
// (named, and without q=0).
func acceptsGzip(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(v, ",") {
			coding, params, _ := strings.Cut(part, ";")
			if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
				continue
			}
			q, isQ := strings.CutPrefix(strings.TrimSpace(params), "q=")
			f, err := strconv.ParseFloat(q, 64)
			return !isQ || err != nil || f > 0
		}
	}
	return false
}
