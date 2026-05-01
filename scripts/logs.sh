#!/bin/bash
set -euo pipefail

# ─── Config ───────────────────────────────────────────────
NAMESPACE="${NAMESPACE:-caliman}"
SINCE="${SINCE:-1h}"
MODE="${1:-compose}"   # compose | k8s | all

# ─── Logging ──────────────────────────────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
err() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }

usage() {
  echo "Usage: $0 [compose|k8s|all]"
  echo "  compose  — docker compose logs (default)"
  echo "  k8s      — kubectl logs for all pods in namespace"
  echo "  all      — both"
  echo ""
  echo "Env vars: NAMESPACE, SINCE (e.g. 30m, 1h, 24h)"
  exit 0
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage

show_compose_logs() {
  if command -v docker &>/dev/null; then
    log "Docker Compose logs (follow mode)..."
    docker compose logs -f --tail=100
  else
    err "docker not found"
  fi
}

show_k8s_logs() {
  command -v kubectl &>/dev/null || { err "kubectl not found"; return 1; }
  log "K8s logs from namespace '$NAMESPACE' (since $SINCE)..."
  PODS=$(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
  if [[ -z "$PODS" ]]; then
    err "No pods found in namespace '$NAMESPACE'"
    return 1
  fi
  for pod in $PODS; do
    log "--- Pod: $pod ---"
    kubectl logs "$pod" -n "$NAMESPACE" --since="$SINCE" --tail=200 2>/dev/null || \
      err "Could not get logs for $pod"
  done
}

case "$MODE" in
  compose) show_compose_logs ;;
  k8s)     show_k8s_logs ;;
  all)     show_k8s_logs; show_compose_logs ;;
  *)       err "Unknown mode: $MODE"; usage ;;
esac