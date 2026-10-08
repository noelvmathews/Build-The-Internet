#!/usr/bin/env bash
# End-to-end smoke test against a running acm-dns.
#   ACM_DNS_URL=http://localhost:8000 ./scripts/smoke.sh
set -u
URL="${ACM_DNS_URL:-http://localhost:8000}"
pass=0; fail=0

check() { # name expected_status actual_status body_must_contain actual_body
  if [[ "$2" == "$3" && "$5" == *"$4"* ]]; then
    echo "PASS  $1"; pass=$((pass+1))
  else
    echo "FAIL  $1 (status $3, want $2) body=$5"; fail=$((fail+1))
  fi
}
req() { # method path [body]
  local out
  if [[ $# -ge 3 ]]; then
    out=$(curl -s -m 5 -w '\n%{http_code}' -X "$1" "$URL$2" -H 'Content-Type: application/json' -d "$3")
  else
    out=$(curl -s -m 5 -w '\n%{http_code}' -X "$1" "$URL$2")
  fi
  BODY="${out%$'\n'*}"; CODE="${out##*$'\n'}"
}

req GET  /health;                                 check "health"                 200 "$CODE" '"status":"ok"' "$BODY"
req GET  "/lookup?domain=smoke-svc";              check "lookup unknown -> 404"  404 "$CODE" 'Domain not registered' "$BODY"
req POST /register '{"domain":"smoke-svc"}';      check "register"               200 "$CODE" '"status":"ok"' "$BODY"
req GET  "/lookup?domain=smoke-svc";              check "lookup found"           200 "$CODE" '"destination"' "$BODY"
req POST /register '{"domain":"smoke-svc"}';      check "re-register (restart)"  200 "$CODE" '"status":"ok"' "$BODY"
req POST /register '{}';                          check "missing domain -> 400"  400 "$CODE" "Missing required 'domain' field" "$BODY"
req POST /register '{not json';                   check "bad json -> 400"        400 "$CODE" 'Invalid JSON body' "$BODY"
req POST /register '{"domain":"bad name!"}';      check "invalid name -> 400"    400 "$CODE" 'Invalid domain' "$BODY"
req GET  /register;                               check "wrong method -> 405"    405 "$CODE" 'Method not allowed' "$BODY"
req GET  /health;                                 check "still alive"            200 "$CODE" '"status":"ok"' "$BODY"

echo "---- $pass passed, $fail failed"
[[ $fail -eq 0 ]]
