// Package web embeds the built browser client (web/dist) so the server binary
// can serve it without Node. dist/ is committed; rebuild it with
// `npm run build` in this directory after changing anything under src/.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the contents of dist/ rooted at the directory itself, so
// "index.html" is at the root of the returned file system.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("web: embedded dist missing: " + err.Error()) // cannot happen: //go:embed fails the build first
	}
	return sub
}
