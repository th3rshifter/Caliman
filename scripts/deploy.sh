#!/bin/bash
set -euo pipefail

# ─── Config ───────────────────────────────────────────────
RELEASE="${RELEASE:-caliman}"
CHART="${CHART:-./helm/caliman}"
NAMESPACE="${NAMESPACE:-caliman}"
TIMEOUT="${TIMEOUT:-120s}"
VALUES_FILE="${VALUES_FILE:-}"

# ─── Logging ──────────────────────────────────────────────
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }
die()  { err "$*"; exit 1; }

# ─── Checks ───────────────────────────────────────────────
command -v helm      &>/dev/null || die "helm not found"
command -v kubectl   &>/dev/null || die "kubectl not found"
[[ -d "$CHART" ]]               || die "Helm chart not found: $CHART"

CONTEXT=$(kubectl config current-context 2>/dev/null || echo "unknown")
log "Kubernetes context: $CONTEXT"
log "Deploying release='$RELEASE' namespace='$NAMESPACE' chart='$CHART'"

# ─── Helm lint ────────────────────────────────────────────
log "Linting Helm chart..."
helm lint "$CHART" || die "Helm lint failed — fix chart errors before deploying"

# ─── Build extra args ─────────────────────────────────────
HELM_ARGS=()
[[ -n "$VALUES_FILE" ]] && HELM_ARGS+=(-f "$VALUES_FILE")

# ─── Deploy ───────────────────────────────────────────────
log "Running helm upgrade --install..."
helm upgrade --install "$RELEASE" "$CHART" \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --timeout "$TIMEOUT" \
  --atomic \
  "${HELM_ARGS[@]}"

# ─── Rollout status ───────────────────────────────────────
log "Waiting for rollout..."
kubectl rollout status deployment/"$RELEASE" -n "$NAMESPACE" --timeout="$TIMEOUT" \
  || die "Rollout did not complete successfully"

log "Deploy successful. Pods:"
kubectl get pods -n "$NAMESPACE"