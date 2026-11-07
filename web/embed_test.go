package web

import (
	"io/fs"
	"strings"
	"testing"
)

func TestDistHasIndexAndServiceWorker(t *testing.T) {
	f := Dist()
	b, err := fs.ReadFile(f, "index.html")
	if err != nil || !strings.Contains(string(b), `id="app"`) {
		t.Fatalf("index.html missing or wrong: %v", err)
	}
	for _, n := range []string{"sw.js", "manifest.webmanifest", "icon.svg"} {
		if _, err := fs.Stat(f, n); err != nil {
			t.Errorf("%s missing: %v", n, err)
		}
	}
	if m, _ := fs.Glob(f, "assets/app-*.js"); len(m) != 1 {
		t.Errorf("want exactly one hashed JS bundle, got %v", m)
	}
}
