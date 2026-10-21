#!/usr/bin/env bash
# Replays the CVE-2018-3760 requests against the patched build and runs the
# regression checks. Usage: ./verify-fix.sh [base-url]
set -u
BASE="${1:-http://localhost:3000}"
TRAVERSAL='%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e/%252e%252e'
ASSET_ROOT='/usr/src/blog/app/assets/images'

check() { # expected label url
  local expected="$1" label="$2" url="$3"
  local code body
  body=$(curl -s "$url")
  code=$(curl -s -o /dev/null -w '%{http_code}' "$url")
  if [ "$code" = "$expected" ]; then
    echo "  PASS  ${code}  ${label}"
  else
    echo "  FAIL  ${code} (expected ${expected})  ${label}"
  fi
  if echo "$body" | grep -q '^root:'; then
    echo "  FAIL  response leaks /etc/passwd"
  fi
}

echo "== attack is no longer possible =="
check 404 "traversal -> /etc/passwd" \
  "${BASE}/assets/file:%2f%2f${ASSET_ROOT}/${TRAVERSAL}/etc/passwd"
check 404 "traversal -> /etc/hostname" \
  "${BASE}/assets/file:%2f%2f${ASSET_ROOT}/${TRAVERSAL}/etc/hostname"

echo
echo "== regression: the application still works =="
check 200 "welcome page" "${BASE}/"
check 200 "asset pipeline" "${BASE}/assets/application.css"
