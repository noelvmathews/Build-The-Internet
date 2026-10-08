package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewLevelsAndFormats(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "warn", "json")
	l.Info("hidden")
	l.Warn("shown")
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "shown") {
		t.Fatalf("unexpected output: %q", out)
	}

	buf.Reset()
	l = New(&buf, "garbage", "text") // bad level falls back to info
	l.Info("hello")
	if !strings.Contains(buf.String(), "msg=hello") {
		t.Fatalf("expected text format, got %q", buf.String())
	}
}
