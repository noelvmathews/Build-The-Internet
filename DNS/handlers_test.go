package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"acm-dns/internal/registry"
)

func newServer(mut ...func(*Options)) *Server {
	o := Options{
		Registry: registry.New(0),
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	for _, m := range mut {
		m(&o)
	}
	return New(o)
}

func do(h http.Handler, method, target, body string, mut func(*http.Request)) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if mut != nil {
		mut(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func asMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response is not a JSON object: %q (%v)", rec.Body.String(), err)
	}
	return m
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, code int) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}

func wantError(t *testing.T, rec *httptest.ResponseRecorder, code int, msg string) {
	t.Helper()
	wantStatus(t, rec, code)
	if got := asMap(t, rec)["error"]; got != msg {
		t.Fatalf("error = %v, want %q", got, msg)
	}
}

// ------------------------------------------------------------- registration

func TestRegisterSuccessAndLookup(t *testing.T) {
	h := newServer().Handler()

	rec := do(h, "POST", "/register", `{"domain":"auth-service"}`, nil)
	wantStatus(t, rec, 200)
	if m := asMap(t, rec); m["status"] != "ok" {
		t.Fatalf("body = %v", m)
	}

	rec = do(h, "GET", "/lookup?domain=auth-service", "", nil)
	wantStatus(t, rec, 200)
	m := asMap(t, rec)
	// httptest requests originate from 192.0.2.1
	if m["domain"] != "auth-service" || m["destination"] != "192.0.2.1" {
		t.Fatalf("lookup body = %v", m)
	}
}

func TestRegisterUsesConnectionIPNotHeaders(t *testing.T) {
	h := newServer().Handler()
	do(h, "POST", "/register", `{"domain":"acm-db"}`, func(r *http.Request) {
		r.RemoteAddr = "10.1.2.3:5555"
		r.Header.Set("X-Forwarded-For", "6.6.6.6")
		r.Header.Set("X-Real-IP", "6.6.6.6")
		r.Header.Set("Forwarded", "for=6.6.6.6")
	})
	m := asMap(t, do(h, "GET", "/lookup?domain=acm-db", "", nil))
	if m["destination"] != "10.1.2.3" {
		t.Fatalf("destination = %v, want 10.1.2.3", m["destination"])
	}
}

func TestRegisterNormalizesSourceIP(t *testing.T) {
	cases := map[string]string{
		"[::ffff:10.0.0.5]:4000": "10.0.0.5",
		"[::1]:4000":             "::1",
		"[fe80::1%eth0]:4000":    "fe80::1",
		"10.0.0.9":               "10.0.0.9", // no port
	}
	for remote, want := range cases {
		h := newServer().Handler()
		rec := do(h, "POST", "/register", `{"domain":"svc"}`, func(r *http.Request) { r.RemoteAddr = remote })
		wantStatus(t, rec, 200)
		m := asMap(t, do(h, "GET", "/lookup?domain=svc", "", nil))
		if m["destination"] != want {
			t.Errorf("remote %q -> %v, want %q", remote, m["destination"], want)
		}
	}
}

func TestRegisterBadRemoteAddr(t *testing.T) {
	h := newServer().Handler()
	rec := do(h, "POST", "/register", `{"domain":"svc"}`, func(r *http.Request) { r.RemoteAddr = "not-an-ip" })
	wantError(t, rec, 400, "Could not determine client address")
}

func TestRegisterErrors(t *testing.T) {
	h := newServer().Handler()
	cases := []struct {
		name, body, msg string
	}{
		{"empty body", ``, "Invalid JSON body"},
		{"malformed json", `{"domain":`, "Invalid JSON body"},
		{"not json", `hello`, "Invalid JSON body"},
		{"array", `[]`, "Invalid JSON body"},
		{"wrong type", `{"domain":123}`, "Invalid JSON body"},
		{"missing field", `{}`, "Missing required 'domain' field"},
		{"null domain", `{"domain":null}`, "Missing required 'domain' field"},
		{"empty domain", `{"domain":""}`, "Missing required 'domain' field"},
		{"blank domain", `{"domain":"   "}`, "Missing required 'domain' field"},
		{"other field only", `{"name":"x"}`, "Missing required 'domain' field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantError(t, do(h, "POST", "/register", c.body, nil), 400, c.msg)
		})
	}
}

func TestRegisterInvalidDomains(t *testing.T) {
	h := newServer().Handler()
	for _, d := range []string{"a b", "http://evil", "a/b", "x@y", "a..b", `a\"b`, "ünï", strings.Repeat("a", 64)} {
		body, _ := json.Marshal(map[string]string{"domain": d})
		rec := do(h, "POST", "/register", string(body), nil)
		wantStatus(t, rec, 400)
		if msg, _ := asMap(t, rec)["error"].(string); !strings.HasPrefix(msg, "Invalid domain:") {
			t.Errorf("domain %q: error = %q", d, msg)
		}
	}
}

func TestRegisterIgnoresUnknownFieldsAndContentType(t *testing.T) {
	h := newServer().Handler()
	rec := do(h, "POST", "/register", `{"domain":"acm-db","port":8002,"extra":{"a":1}}`, func(r *http.Request) {
		r.Header.Set("Content-Type", "text/plain")
	})
	wantStatus(t, rec, 200)
	wantStatus(t, do(h, "POST", "/register", `{"domain":"acm-app"}`, nil), 200) // no Content-Type at all
}

func TestRegisterHugePayload(t *testing.T) {
	h := newServer().Handler()
	body := `{"domain":"` + strings.Repeat("a", 2<<20) + `"}`
	wantError(t, do(h, "POST", "/register", body, nil), 400, "Request body too large")
	// server still healthy afterwards
	wantStatus(t, do(h, "POST", "/register", `{"domain":"ok"}`, nil), 200)
}

func TestRegisterDuplicateOverwrites(t *testing.T) {
	h := newServer().Handler()
	do(h, "POST", "/register", `{"domain":"acm-db"}`, func(r *http.Request) { r.RemoteAddr = "10.0.0.1:1" })
	rec := do(h, "POST", "/register", `{"domain":"acm-db"}`, func(r *http.Request) { r.RemoteAddr = "10.0.0.2:1" })
	wantStatus(t, rec, 200)
	if m := asMap(t, do(h, "GET", "/lookup?domain=acm-db", "", nil)); m["destination"] != "10.0.0.2" {
		t.Fatalf("destination = %v, want latest IP", m["destination"])
	}
}

func TestRegisterCaseInsensitive(t *testing.T) {
	h := newServer().Handler()
	do(h, "POST", "/register", `{"domain":"ACM-DB"}`, nil)
	m := asMap(t, do(h, "GET", "/lookup?domain=Acm-Db", "", nil))
	if m["domain"] != "acm-db" {
		t.Fatalf("body = %v", m)
	}
}

func TestAllowlist(t *testing.T) {
	h := newServer(func(o *Options) {
		o.AllowedDomains = map[string]struct{}{"acm-db": {}}
	}).Handler()
	wantStatus(t, do(h, "POST", "/register", `{"domain":"acm-db"}`, nil), 200)
	wantError(t, do(h, "POST", "/register", `{"domain":"evil"}`, nil), 403, "Domain not permitted")
	wantError(t, do(h, "GET", "/lookup?domain=evil", "", nil), 404, "Domain not registered")
}

// ---------------------------------------------------------------- discovery

func TestLookupUnknown(t *testing.T) {
	h := newServer().Handler() // empty registry
	wantError(t, do(h, "GET", "/lookup?domain=ghost", "", nil), 404, "Domain not registered")
}

func TestLookupBadRequests(t *testing.T) {
	h := newServer().Handler()
	wantError(t, do(h, "GET", "/lookup", "", nil), 400, "Missing required 'domain' query parameter")
	wantError(t, do(h, "GET", "/lookup?domain=", "", nil), 400, "Missing required 'domain' query parameter")
	wantStatus(t, do(h, "GET", "/lookup?domain=a%20b", "", nil), 400)
}

func TestLookupMultipleServices(t *testing.T) {
	h := newServer().Handler()
	for i, d := range []string{"acm-db", "acm-server", "acm-app"} {
		ip := fmt.Sprintf("10.0.0.%d:1", i+1)
		do(h, "POST", "/register", `{"domain":"`+d+`"}`, func(r *http.Request) { r.RemoteAddr = ip })
	}
	for i, d := range []string{"acm-db", "acm-server", "acm-app"} {
		m := asMap(t, do(h, "GET", "/lookup?domain="+d, "", nil))
		if want := fmt.Sprintf("10.0.0.%d", i+1); m["destination"] != want {
			t.Errorf("%s -> %v, want %s", d, m["destination"], want)
		}
	}
}

func TestTTLExpiryThroughAPI(t *testing.T) {
	reg := registry.New(1) // 1ns: expires immediately
	h := newServer(func(o *Options) { o.Registry = reg }).Handler()
	wantStatus(t, do(h, "POST", "/register", `{"domain":"acm-db"}`, nil), 200)
	wantError(t, do(h, "GET", "/lookup?domain=acm-db", "", nil), 404, "Domain not registered")
}

// --------------------------------------------------------------------- HTTP

func TestMethodNotAllowed(t *testing.T) {
	h := newServer().Handler()
	rec := do(h, "GET", "/register", "", nil)
	wantError(t, rec, 405, "Method not allowed")
	if rec.Header().Get("Allow") != "POST" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
	rec = do(h, "POST", "/lookup?domain=x", `{}`, nil)
	wantError(t, rec, 405, "Method not allowed")
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
	wantStatus(t, do(h, "DELETE", "/register", "", nil), 405)
	wantStatus(t, do(h, "PUT", "/lookup?domain=x", "", nil), 405)
}

func TestUnknownPathIsJSON404(t *testing.T) {
	h := newServer().Handler()
	wantError(t, do(h, "GET", "/nope", "", nil), 404, "Not found")
	wantError(t, do(h, "GET", "/", "", nil), 404, "Not found")
	wantError(t, do(h, "GET", "/lookup/", "", nil), 404, "Not found")
}

func TestHeadersAndCORS(t *testing.T) {
	h := newServer(func(o *Options) { o.CORSOrigin = "*" }).Handler()
	rec := do(h, "GET", "/health", "", nil)
	if rec.Header().Get("Cache-Control") != "no-store" ||
		rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("headers = %v", rec.Header())
	}
	rec = do(h, "OPTIONS", "/register", "", nil)
	if rec.Code != 204 || rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Fatalf("preflight: %d %v", rec.Code, rec.Header())
	}
}

func TestHealthAndMetrics(t *testing.T) {
	h := newServer().Handler()
	do(h, "POST", "/register", `{"domain":"acm-db"}`, nil)
	do(h, "POST", "/register", `{}`, nil)
	do(h, "GET", "/lookup?domain=acm-db", "", nil)
	do(h, "GET", "/lookup?domain=ghost", "", nil)

	rec := do(h, "GET", "/health", "", nil)
	wantStatus(t, rec, 200)
	m := asMap(t, rec)
	want := map[string]float64{"domains": 1, "registrations": 1, "register_failures": 1, "lookups": 2, "lookup_misses": 1}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v", k, m[k], v)
		}
	}
	if m["status"] != "ok" {
		t.Errorf("status = %v", m["status"])
	}
}

func TestEventsEndpoint(t *testing.T) {
	h := newServer().Handler()
	do(h, "POST", "/register", `{"domain":"acm-db"}`, nil)
	do(h, "GET", "/lookup?domain=acm-db", "", nil)
	do(h, "GET", "/lookup?domain=ghost", "", nil)

	rec := do(h, "GET", "/events", "", nil)
	wantStatus(t, rec, 200)
	evs := asMap(t, rec)["events"].([]any)
	if len(evs) != 3 {
		t.Fatalf("got %d events: %v", len(evs), evs)
	}
	types := []string{}
	for _, e := range evs {
		types = append(types, e.(map[string]any)["type"].(string))
	}
	if strings.Join(types, ",") != "DOMAIN_REGISTERED,LOOKUP_FOUND,LOOKUP_NOT_FOUND" {
		t.Fatalf("types = %v", types)
	}
	// incremental polling
	evs = asMap(t, do(h, "GET", "/events?after=2", "", nil))["events"].([]any)
	if len(evs) != 1 {
		t.Fatalf("after=2 returned %d events", len(evs))
	}
	// empty -> [] not null
	empty := newServer().Handler()
	if body := do(empty, "GET", "/events", "", nil).Body.String(); !strings.Contains(body, `"events":[]`) {
		t.Fatalf("body = %s", body)
	}
}

func TestPanicRecovery(t *testing.T) {
	s := newServer()
	h := s.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("secret internal detail") }))
	rec := do(h, "GET", "/x", "", nil)
	wantError(t, rec, 500, "Internal server error")
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("panic detail leaked to client")
	}
}

// -------------------------------------------------------- concurrency / chaos

func TestConcurrentRegisterAndLookupOverHTTP(t *testing.T) {
	ts := httptest.NewServer(newServer().Handler())
	defer ts.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			name := fmt.Sprintf("svc-%d", g)
			resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(`{"domain":"`+name+`"}`))
			if err != nil {
				errs <- err
				return
			}
			resp.Body.Close()
			for i := 0; i < 50; i++ {
				resp, err := http.Get(ts.URL + "/lookup?domain=" + name)
				if err != nil {
					errs <- err
					return
				}
				var out lookupResponse
				_ = json.NewDecoder(resp.Body).Decode(&out)
				resp.Body.Close()
				if resp.StatusCode != 200 || out.Domain != name || out.Destination != "127.0.0.1" {
					errs <- fmt.Errorf("%s: status=%d body=%+v", name, resp.StatusCode, out)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSurvivesChaos(t *testing.T) {
	ts := httptest.NewServer(newServer().Handler())
	defer ts.Close()

	garbage := []string{``, `{`, `}`, `null`, `[1,2,3]`, `{"domain":{"x":1}}`, "\x00\x01\x02", strings.Repeat("{", 100000)}
	for _, g := range garbage {
		resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(g))
		if err != nil {
			t.Fatalf("request failed for %q: %v", g, err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("garbage %q -> %d, want 400", g, resp.StatusCode)
		}
	}

	resp, err := http.Post(ts.URL+"/register", "application/json", strings.NewReader(`{"domain":"acm-db"}`))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("server not healthy after garbage: %v %v", resp, err)
	}
	resp.Body.Close()
	resp, err = http.Get(ts.URL + "/lookup?domain=acm-db")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("lookup failed after garbage: %v %v", resp, err)
	}
	resp.Body.Close()
}
