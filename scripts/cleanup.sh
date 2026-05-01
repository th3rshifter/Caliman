#!/bin/bash
set -euo pipefail

# ─── Logging ──────────────────────────────────────────────
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
warn() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }
die()  { err "$*"; exit 1; }

# ─── Checks ───────────────────────────────────────────────
command -v docker &>/dev/null || die "docker not found"

# ─── Confirmation ─────────────────────────────────────────
if [[ "${FORCE:-false}" != "true" ]]; then
  warn "This will remove all containers, volumes, and unused Docker data."
  read -rp "Continue? [y/N] " confirm
  [[ "${confirm,,}" == "y" ]] || { log "Aborted."; exit 0; }
fi

# ─── Disk usage before ────────────────────────────────────
BEFORE=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1 || echo "unknown")
log "Docker disk usage before: $(docker system df 2>/dev/null | tail -n +2 | awk '{print $1, $3}' | tr '\n' ' ')"

# ─── Cleanup ──────────────────────────────────────────────
log "Stopping and removing containers (docker compose down -v)..."
docker compose down -v || warn "docker compose down failed (maybe already down)"

log "Pruning unused Docker resources..."
docker system prune -f

log "Cleanup complete."