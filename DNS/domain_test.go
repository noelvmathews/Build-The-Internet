package validate

import (
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	good := map[string]string{
		"auth-service":          "auth-service",
		"  ACM-DB  ":            "acm-db",
		"acm_server":            "acm_server",
		"db.internal.test":      "db.internal.test",
		"a":                     "a",
		strings.Repeat("a", 63): strings.Repeat("a", 63),
	}
	for in, want := range good {
		got, err := NormalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	bad := []string{
		"", "   ", ".", "a..b", ".a", "a.", "has space", "slash/path", "http://x",
		"a:80", "x@y", "unicod\u00e9", "\u212a", "new\nline", "a;b", "a%00",
		strings.Repeat("a", 64),
		strings.Repeat("a.", 130) + "a",
	}
	for _, in := range bad {
		if got, err := NormalizeDomain(in); err == nil {
			t.Errorf("NormalizeDomain(%q) = %q, nil; want error", in, got)
		}
	}
}
