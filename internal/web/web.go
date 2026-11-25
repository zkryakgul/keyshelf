// Package web holds the embedded web UI: plain HTML, CSS and JavaScript, no framework, no CDN.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var static embed.FS

// Files returns the UI files, rooted at the directory that holds index.html.
func Files() fs.FS {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
