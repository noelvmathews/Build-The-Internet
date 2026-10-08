// Package handlers implements the acm-dns HTTP API defined in openapi.yaml:
//
//	GET  /lookup?domain=<name>   -> 200 {"domain","destination"} | 404 {"error"}
//	POST /register {"domain"}    -> 200 {"status":"ok"}          | 400 {"error"}
//
// Additive, non-contract endpoints: GET /health and GET /events.
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"acm-dns/internal/events"
	"acm-dns/internal/registry"
	"acm-dns/internal/validate"
)

// Options configures a Server.
type Options struct {
	Registry       *registry.Registry
	Logger         *slog.Logger
	Events         *events.Log
	AllowedDomains map[string]struct{} // nil = any valid domain
	CORSOrigin     string              // "" = disabled
	MaxBodyBytes   int64               // default 1 MiB
}

// Server holds the HTTP handlers and shared state.
type Server struct {
	reg     *registry.Registry
	log     *slog.Logger
	ev      *events.Log
	allowed map[string]struct{}
	cors    string
	maxBody int64
	started time.Time

	registrations    atomic.Int64
	registerFailures atomic.Int64
	lookups          atomic.Int64
	lookupMisses     atomic.Int64
}

// New builds a Server. Registry is required.
func New(o Options) *Server {
	s := &Server{
		reg:     o.Registry,
		log:     o.Logger,
		ev:      o.Events,
		allowed: o.AllowedDomains,
		cors:    o.CORSOrigin,
		maxBody: o.MaxBodyBytes,
		started: time.Now(),
	}
	if s.reg == nil {
		s.reg = registry.New(0)
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.ev == nil {
		s.ev = events.NewLog(500)
	}
	if s.maxBody <= 0 {
		s.maxBody = 1 << 20
	}
	return s
}

// Handler returns the fully wired http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/lookup", s.handleLookup)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/events", s.handleEvents)
	mux.HandleFunc("/", s.handleNotFound)
	return s.wrap(mux)
}

// OnExpire is the registry sweeper callback.
func (s *Server) OnExpire(e registry.Entry) {
	s.log.Info(events.DomainExpired, "domain", e.Domain, "ip", e.IP)
	s.ev.Add(events.DomainExpired, e.Domain, e.IP, "lease expired")
}

// ---------------------------------------------------------------- /register

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		msg := "Invalid JSON body"
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			msg = "Request body too large"
		}
		s.registerFailed(w, "", "invalid_json", msg)
		return
	}

	if strings.TrimSpace(req.Domain) == "" {
		s.registerFailed(w, "", "missing_domain", "Missing required 'domain' field")
		return
	}
	domain, err := validate.NormalizeDomain(req.Domain)
	if err != nil {
		s.registerFailed(w, "", "invalid_domain", "Invalid domain: "+err.Error())
		return
	}
	if s.allowed != nil {
		if _, ok := s.allowed[domain]; !ok {
			s.registerFailed2(w, http.StatusForbidden, domain, "not_allowed", "Domain not permitted")
			return
		}
	}

	// Source IP comes from the TCP connection only. X-Forwarded-For and
	// similar headers are client-controlled and deliberately ignored.
	ip, err := sourceIP(r)
	if err != nil {
		s.registerFailed(w, domain, "bad_remote_addr", "Could not determine client address")
		return
	}

	prevIP, existed := s.reg.Register(domain, ip)
	s.registrations.Add(1)
	if existed {
		detail := "refreshed"
		if prevIP != ip {
			detail = "ip changed from " + prevIP
		}
		s.log.Info(events.DomainUpdated, "domain", domain, "ip", ip, "prev_ip", prevIP)
		s.ev.Add(events.DomainUpdated, domain, ip, detail)
	} else {
		s.log.Info(events.DomainRegistered, "domain", domain, "ip", ip)
		s.ev.Add(events.DomainRegistered, domain, ip, "")
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) registerFailed(w http.ResponseWriter, domain, reason, msg string) {
	s.registerFailed2(w, http.StatusBadRequest, domain, reason, msg)
}

func (s *Server) registerFailed2(w http.ResponseWriter, status int, domain, reason, msg string) {
	s.registerFailures.Add(1)
	s.log.Warn(events.RegisterFailed, "domain", domain, "reason", reason, "status", status)
	s.ev.Add(events.RegisterFailed, domain, "", reason)
	writeError(w, status, msg)
}

// ------------------------------------------------------------------ /lookup

type lookupResponse struct {
	Domain      string `json:"domain"`
	Destination string `json:"destination"`
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	start := time.Now()
	s.lookups.Add(1)
	requester := remoteHost(r)

	raw := r.URL.Query().Get("domain")
	if strings.TrimSpace(raw) == "" {
		s.lookupFailed(w, "", requester, "missing_domain", "Missing required 'domain' query parameter")
		return
	}
	domain, err := validate.NormalizeDomain(raw)
	if err != nil {
		s.lookupFailed(w, "", requester, "invalid_domain", "Invalid domain: "+err.Error())
		return
	}

	e, ok := s.reg.Lookup(domain)
	if !ok {
		s.lookupMisses.Add(1)
		s.log.Info(events.LookupNotFound, "target", domain, "requester_ip", requester,
			"latency_us", time.Since(start).Microseconds())
		s.ev.Add(events.LookupNotFound, domain, "", "requester="+requester)
		writeError(w, http.StatusNotFound, "Domain not registered")
		return
	}

	s.log.Info(events.LookupFound, "target", domain, "destination", e.IP, "requester_ip", requester,
		"latency_us", time.Since(start).Microseconds())
	s.ev.Add(events.LookupFound, domain, e.IP, "requester="+requester)
	writeJSON(w, http.StatusOK, lookupResponse{Domain: domain, Destination: e.IP})
}

func (s *Server) lookupFailed(w http.ResponseWriter, domain, requester, reason, msg string) {
	s.log.Warn(events.LookupFailed, "target", domain, "requester_ip", requester, "reason", reason)
	s.ev.Add(events.LookupFailed, domain, "", reason)
	writeError(w, http.StatusBadRequest, msg)
}

// ------------------------------------------------- additive utility endpoints

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "ok",
		"domains":           s.reg.Len(),
		"ttl_seconds":       int64(s.reg.TTL().Seconds()),
		"uptime_seconds":    int64(time.Since(s.started).Seconds()),
		"registrations":     s.registrations.Load(),
		"register_failures": s.registerFailures.Load(),
		"lookups":           s.lookups.Load(),
		"lookup_misses":     s.lookupMisses.Load(),
	})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	writeJSON(w, http.StatusOK, map[string]any{"events": s.ev.Since(after)})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "Not found")
}

// --------------------------------------------------------------- middleware

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.wrote = true
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

// wrap adds panic recovery, hardening headers, optional CORS and debug logging.
func (s *Server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				s.log.Error("PANIC_RECOVERED", "panic", fmt.Sprint(rec), "method", r.Method, "path", r.URL.Path)
				if !sw.wrote {
					writeError(sw, http.StatusInternalServerError, "Internal server error")
				}
			}
			s.log.Debug("HTTP_REQUEST", "method", r.Method, "path", r.URL.Path,
				"status", sw.status, "remote", remoteHost(r), "latency_us", time.Since(start).Microseconds())
		}()

		h := sw.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		if s.cors != "" {
			h.Set("Access-Control-Allow-Origin", s.cors)
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type")
				sw.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(sw, r)
	})
}

// ------------------------------------------------------------------ helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
}

// remoteHost returns the connection's source host (best effort, for logs).
func remoteHost(r *http.Request) string {
	ip, err := sourceIP(r)
	if err != nil {
		return "unknown"
	}
	return ip
}

// sourceIP extracts the caller's IP from the TCP connection, with the port and
// IPv6 zone stripped and IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) unmapped.
func sourceIP(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", err
	}
	return addr.Unmap().WithZone("").String(), nil
}
