#!/bin/bash
set -euo pipefail

# ─── Config ───────────────────────────────────────────────
HOST="${HOST:-localhost}"
PORT="${PORT:-8080}"
TIMEOUT="${TIMEOUT:-5}"
RETRIES="${RETRIES:-3}"
BASE_URL="http://${HOST}:${PORT}"

# ─── Logging ──────────────────────────────────────────────
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
ok()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]    ✓ $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [FAIL]  ✗ $*" >&2; }

PASSED=0
FAILED=0

# ─── HTTP test helper ─────────────────────────────────────
smoke_test() {
  local method="${1:-GET}"
  local path="$2"
  local expected_status="${3:-200}"
  local label="${method} ${path} → expect ${expected_status}"
  local url="${BASE_URL}${path}"
  local attempt=0
  local status

  while [[ $attempt -lt $RETRIES ]]; do
    status=$(curl -o /dev/null -s -w "%{http_code}" \
      -X "$method" \
      --max-time "$TIMEOUT" \
      "$url" 2>/dev/null || echo "000")

    if [[ "$status" == "$expected_status" ]]; then
      ok "$label (attempt $((attempt+1)))"
      PASSED=$((PASSED+1))
      return 0
    fi

    attempt=$((attempt+1))
    [[ $attempt -lt $RETRIES ]] && sleep 1
  done

  err "$label — got HTTP $status after $RETRIES attempts"
  FAILED=$((FAILED+1))
}

# ─── Test suite ───────────────────────────────────────────
log "Running smoke tests against $BASE_URL"
log "────────────────────────────────────────"

smoke_test GET /health 200
smoke_test GET /ready  200

# Add more endpoints here as your app grows:
# smoke_test GET  /api/v1/status 200
# smoke_test POST /api/v1/echo   200

# ─── Summary ──────────────────────────────────────────────
log "────────────────────────────────────────"
log "Results: ${PASSED} passed, ${FAILED} failed"

if [[ "$FAILED" -gt 0 ]]; then
  err "Smoke tests FAILED."
  exit 1
else
  ok "All smoke tests passed."
fi