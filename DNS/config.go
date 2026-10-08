// Package config loads acm-dns settings from environment variables.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"acm-dns/internal/validate"
)

type Config struct {
	Host           string
	Port           int
	TTL            time.Duration       // 0 = registrations never expire
	AllowedDomains map[string]struct{} // nil = any valid domain may register
	CORSOrigin     string              // "" = CORS disabled
	LogLevel       string
	LogFormat      string
}

// Addr returns the host:port the HTTP server should listen on.
func (c Config) Addr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// Load reads configuration from the process environment.
func Load() (Config, error) { return LoadFrom(os.Getenv) }

// LoadFrom reads configuration using the supplied getter (testable).
func LoadFrom(get func(string) string) (Config, error) {
	cfg := Config{
		Host:       orDefault(get("ACM_DNS_HOST"), "0.0.0.0"),
		Port:       8000,
		CORSOrigin: strings.TrimSpace(get("ACM_DNS_CORS_ORIGIN")),
		LogLevel:   orDefault(get("ACM_DNS_LOG_LEVEL"), "info"),
		LogFormat:  orDefault(get("ACM_DNS_LOG_FORMAT"), "json"),
	}

	if v := strings.TrimSpace(get("ACM_DNS_PORT")); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return Config{}, fmt.Errorf("ACM_DNS_PORT must be an integer between 1 and 65535, got %q", v)
		}
		cfg.Port = p
	}

	if v := strings.TrimSpace(get("ACM_DNS_TTL")); v != "" {
		ttl, err := time.ParseDuration(v)
		if err != nil {
			secs, err2 := strconv.Atoi(v) // plain integer = seconds
			if err2 != nil {
				return Config{}, fmt.Errorf("ACM_DNS_TTL must be a duration like 30s or a number of seconds, got %q", v)
			}
			ttl = time.Duration(secs) * time.Second
		}
		if ttl < 0 {
			return Config{}, fmt.Errorf("ACM_DNS_TTL must not be negative, got %q", v)
		}
		cfg.TTL = ttl
	}

	if v := strings.TrimSpace(get("ACM_DNS_ALLOWED_DOMAINS")); v != "" {
		allowed := make(map[string]struct{})
		for _, part := range strings.Split(v, ",") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			d, err := validate.NormalizeDomain(part)
			if err != nil {
				return Config{}, fmt.Errorf("ACM_DNS_ALLOWED_DOMAINS has invalid entry %q: %v", part, err)
			}
			allowed[d] = struct{}{}
		}
		if len(allowed) > 0 {
			cfg.AllowedDomains = allowed
		}
	}
	return cfg, nil
}

func orDefault(v, def string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}
