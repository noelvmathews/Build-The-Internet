package config

import (
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	cfg, err := LoadFrom(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "0.0.0.0" || cfg.Port != 8000 || cfg.TTL != 0 || cfg.AllowedDomains != nil {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.Addr() != "0.0.0.0:8000" {
		t.Fatalf("Addr = %q", cfg.Addr())
	}
}

func TestCustomValues(t *testing.T) {
	cfg, err := LoadFrom(env(map[string]string{
		"ACM_DNS_HOST":            "127.0.0.1",
		"ACM_DNS_PORT":            "9090",
		"ACM_DNS_TTL":             "30s",
		"ACM_DNS_ALLOWED_DOMAINS": "ACM-DB, acm-server,,acm-app",
		"ACM_DNS_CORS_ORIGIN":     "*",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr() != "127.0.0.1:9090" || cfg.TTL != 30*time.Second || cfg.CORSOrigin != "*" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	for _, d := range []string{"acm-db", "acm-server", "acm-app"} {
		if _, ok := cfg.AllowedDomains[d]; !ok {
			t.Errorf("missing allowed domain %q", d)
		}
	}
}

func TestTTLPlainSeconds(t *testing.T) {
	cfg, err := LoadFrom(env(map[string]string{"ACM_DNS_TTL": "45"}))
	if err != nil || cfg.TTL != 45*time.Second {
		t.Fatalf("got %v, %v", cfg.TTL, err)
	}
}

func TestInvalid(t *testing.T) {
	cases := []map[string]string{
		{"ACM_DNS_PORT": "abc"},
		{"ACM_DNS_PORT": "0"},
		{"ACM_DNS_PORT": "70000"},
		{"ACM_DNS_TTL": "soon"},
		{"ACM_DNS_TTL": "-5s"},
		{"ACM_DNS_ALLOWED_DOMAINS": "ok,bad name"},
	}
	for _, c := range cases {
		if _, err := LoadFrom(env(c)); err == nil {
			t.Errorf("expected error for %v", c)
		}
	}
}
