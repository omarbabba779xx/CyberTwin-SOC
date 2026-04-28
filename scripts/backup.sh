#!/usr/bin/env bash
# CyberTwin SOC — Backup Script
# Usage: ./scripts/backup.sh [backup_dir]
# Backs up PostgreSQL, Redis, and configuration
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

BACKUP_DIR="${1:-/tmp/cybertwin-backup-$(date +%Y%m%d_%H%M%S)}"
STAGING_DIR="$BACKUP_DIR/staging"
ARCHIVE="$BACKUP_DIR.tar.gz"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() { log "ERROR: $*" >&2; exit 1; }

mkdir -p "$STAGING_DIR"

# ── PostgreSQL ────────────────────────────────────────────────────────────
if [[ -n "${DATABASE_URL:-}" ]]; then
    log "Dumping PostgreSQL..."
    pg_dump "$DATABASE_URL" --no-owner --no-acl \
        -f "$STAGING_DIR/postgres.sql" \
        || fail "pg_dump failed (exit $?)"
    log "PostgreSQL dump saved."
else
    log "DATABASE_URL not set — skipping PostgreSQL backup."
fi

# ── Redis ─────────────────────────────────────────────────────────────────
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_DUMP="${REDIS_DUMP_PATH:-/var/lib/redis/dump.rdb}"

if command -v redis-cli &>/dev/null; then
    log "Triggering Redis BGSAVE..."
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" BGSAVE >/dev/null 2>&1 || true
    sleep 2  # allow the save to flush

    if [[ -f "$REDIS_DUMP" ]]; then
        cp "$REDIS_DUMP" "$STAGING_DIR/redis-dump.rdb"
        log "Redis dump copied."
    else
        log "Redis dump.rdb not found at $REDIS_DUMP — skipping."
    fi
else
    log "redis-cli not found — skipping Redis backup."
fi

# ── Configuration files ───────────────────────────────────────────────────
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    cp "$PROJECT_ROOT/.env" "$STAGING_DIR/env.bak"
    log ".env backed up."
fi

if compgen -G "$PROJECT_ROOT/scenarios/*.json" >/dev/null 2>&1; then
    mkdir -p "$STAGING_DIR/scenarios"
    cp "$PROJECT_ROOT"/scenarios/*.json "$STAGING_DIR/scenarios/"
    log "Scenario JSON files backed up."
fi

# ── Archive ───────────────────────────────────────────────────────────────
log "Compressing to $ARCHIVE ..."
tar -czf "$ARCHIVE" -C "$BACKUP_DIR" staging
rm -rf "$STAGING_DIR"

log "Backup complete: $ARCHIVE"
echo "$ARCHIVE"
exit 0
