#!/bin/bash
set -euo pipefail

# ─── Config ───────────────────────────────────────────────
HOST="${HOST:-localhost}"
PORT="${PORT:-8080}"
NAMESPACE="${NAMESPACE:-caliman}"
TIMEOUT="${TIMEOUT:-5}"
BASE_URL="http://${HOST}:${PORT}"

# ─── Logging ──────────────────────────────────────────────
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
ok()   { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [OK]    $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }

FAILED=0

check_http() {
  local url="$1"
  local label="$2"
  local status
  status=$(curl -o /dev/null -s -w "%{http_code}" --max-time "$TIMEOUT" "$url" || echo "000")
  if [[ "$status" == "200" ]]; then
    ok "$label → HTTP $status"
  else
    err "$label → HTTP $status (expected 200)"
    FAILED=1
  fi
}

# ─── HTTP checks ──────────────────────────────────────────
log "Checking application endpoints at $BASE_URL..."
check_http "${BASE_URL}/health" "/health"
check_http "${BASE_URL}/ready"  "/ready"

# ─── K8s pods ─────────────────────────────────────────────
if command -v kubectl &>/dev/null; then
  log "Kubernetes pods in namespace '$NAMESPACE':"
  kubectl get pods -n "$NAMESPACE" \
    -o custom-columns='NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready'

  NOT_READY=$(kubectl get pods -n "$NAMESPACE" \
    --field-selector=status.phase!=Running 2>/dev/null | grep -vc "^NAME" || true)
  [[ "$NOT_READY" -gt 0 ]] && { err "$NOT_READY pod(s) not Running"; FAILED=1; }
else
  log "kubectl not found, skipping K8s check"
fi

# ─── Docker Compose ───────────────────────────────────────
if command -v docker &>/dev/null; then
  log "Docker Compose services:"
  docker compose ps 2>/dev/null || log "No docker compose services found"
fi

# ─── Result ───────────────────────────────────────────────
if [[ "$FAILED" -eq 0 ]]; then
  ok "All health checks passed."
else
  err "One or more health checks FAILED."
  exit 1
fi