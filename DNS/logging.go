// Package logging builds the structured logger used by acm-dns.
package logging

import (
	"io"
	"log/slog"
	"strings"
)

// New returns a slog logger. level: debug|info|warn|error (default info).
// format: "json" (default) or "text".
func New(w io.Writer, level, format string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	if strings.EqualFold(strings.TrimSpace(format), "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}
	return slog.New(h)
}
