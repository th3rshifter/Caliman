#!/bin/bash
set -euo pipefail

# ─── Config ───────────────────────────────────────────────
RELEASE="${RELEASE:-caliman}"
NAMESPACE="${NAMESPACE:-caliman}"
REVISION="${1:-}"   # optional: specific revision number
TIMEOUT="${TIMEOUT:-60s}"

# ─── Logging ──────────────────────────────────────────────
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }
die()  { err "$*"; exit 1; }

# ─── Checks ───────────────────────────────────────────────
command -v helm    &>/dev/null || die "helm not found"
command -v kubectl &>/dev/null || die "kubectl not found"

CONTEXT=$(kubectl config current-context 2>/dev/null || echo "unknown")
log "Kubernetes context: $CONTEXT"

# ─── Show history ─────────────────────────────────────────
log "Helm history for release '$RELEASE':"
helm history "$RELEASE" -n "$NAMESPACE" 2>/dev/null || die "Release '$RELEASE' not found in namespace '$NAMESPACE'"

# ─── Determine revision ───────────────────────────────────
if [[ -z "$REVISION" ]]; then
  warn "No revision specified — rolling back to previous revision"
  ROLLBACK_ARGS=("$RELEASE")
else
  log "Rolling back to revision $REVISION"
  ROLLBACK_ARGS=("$RELEASE" "$REVISION")
fi

# ─── Confirmation ─────────────────────────────────────────
if [[ "${FORCE:-false}" != "true" ]]; then
  read -rp "Confirm rollback of '$RELEASE' in '$NAMESPACE'? [y/N] " confirm
  [[ "${confirm,,}" == "y" ]] || { log "Aborted."; exit 0; }
fi

# ─── Rollback ─────────────────────────────────────────────
log "Executing rollback..."
helm rollback "${ROLLBACK_ARGS[@]}" \
  -n "$NAMESPACE" \
  --wait \
  --timeout "$TIMEOUT" \
  || die "Rollback failed"

# ─── Status ───────────────────────────────────────────────
log "Rollback complete. Current pods:"
kubectl get pods -n "$NAMESPACE"

log "Current helm release status:"
helm status "$RELEASE" -n "$NAMESPACE" | grep -E "STATUS|REVISION|LAST DEPLOYED"