#!/usr/bin/env bash
# Replays the CVE-2018-3760 requests against the patched build (Sprockets 3.7.2)
# and runs the regression checks. Usage: ./verify-fix.sh [base-url]
set -u
BASE="${1:-http://localhost:3000}"
TRAVERSAL='%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e'
ASSET_ROOT='/usr/src/blog/app/assets/images'
fail=0

check() { # expected label url
  local expected="$1" label="$2" url="$3"
  local code body
  code=$(curl -s -o /dev/null -w '%{http_code}' "$url")
  body=$(curl -s "$url")
  if [ "$code" = "$expected" ]; then
    echo "  PASS  HTTP ${code}  ${label}"
  else
    echo "  FAIL  HTTP ${code} (expected ${expected})  ${label}"
    fail=1
  fi
  if echo "$body" | grep -q '^root:'; then
    echo "  FAIL  response still leaks /etc/passwd"
    fail=1
  fi
}

echo "== the attack no longer succeeds =="
check 403 "file:// asset outside the root" "${BASE}/assets/file:%2f%2f/etc/passwd"
check 403 "double encoded traversal -> /etc/passwd" \
  "${BASE}/assets/file:%2f%2f${ASSET_ROOT}/${TRAVERSAL}/etc/passwd"
check 403 "double encoded traversal -> /etc/hostname" \
  "${BASE}/assets/file:%2f%2f${ASSET_ROOT}/${TRAVERSAL}/etc/hostname"

echo
echo "== regression: the application still works =="
check 200 "welcome page" "${BASE}/"
check 200 "asset pipeline (application.js)" "${BASE}/assets/application.js"

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: fix verified"; else echo "RESULT: FAILED"; exit 1; fi
