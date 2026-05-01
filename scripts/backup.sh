#!/bin/bash
set -euo pipefail

# ─── Config ───────────────────────────────────────────────
BACKUP_DIR="${BACKUP_DIR:-./backups}"
VOLUME="${VOLUME:-prometheus-data}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="prometheus-backup-${TIMESTAMP}.tar.gz"
RETENTION_DAYS="${RETENTION_DAYS:-7}"

# ─── Logging ──────────────────────────────────────────────
log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*"; }
err()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2; }
die()  { err "$*"; exit 1; }

# ─── Checks ───────────────────────────────────────────────
command -v docker &>/dev/null || die "docker not found"
docker volume inspect "$VOLUME" &>/dev/null || die "Volume '$VOLUME' does not exist"

mkdir -p "$BACKUP_DIR"

# ─── Backup ───────────────────────────────────────────────
log "Starting backup of volume '$VOLUME' → $BACKUP_FILE"

docker run --rm \
  -v "${VOLUME}:/data:ro" \
  -v "$(pwd)/${BACKUP_DIR}:/backup" \
  alpine tar czf "/backup/${BACKUP_FILE}" /data \
  || die "Backup failed"

BACKUP_SIZE=$(du -sh "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)
log "Backup complete: ${BACKUP_DIR}/${BACKUP_FILE} (${BACKUP_SIZE})"

# ─── Cleanup old backups ──────────────────────────────────
log "Removing backups older than ${RETENTION_DAYS} days..."
find "$BACKUP_DIR" -name "prometheus-backup-*.tar.gz" \
  -mtime +"$RETENTION_DAYS" -delete -print | while read -r f; do
  log "Deleted old backup: $f"
done

log "Done."