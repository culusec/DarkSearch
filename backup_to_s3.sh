#!/usr/bin/env bash
#
# backup_to_s3.sh — Daily backup of the darkweb search engine SQLite DB to S3
#
# Uses Python's sqlite3 backup() API to safely snapshot a live database,
# then gzip-compresses and uploads to S3.
#
# Target: s3://threat-intel-raw-dumps/darkweb-search-engine/
#
set -euo pipefail

DB_PATH="/mnt/darkweb/index.db"
S3_BUCKET="threat-intel-raw-dumps"
S3_PREFIX="darkweb-search-engine"
DATESTAMP=$(date +%Y-%m-%d)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TMP_DIR="/tmp/darkweb_backup"
LOG="/mnt/darkweb/logs/backup_s3.log"

mkdir -p "$TMP_DIR" "$(dirname "$LOG")"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG"; }

log "=== Backup started ==="

# --- 1. Safe SQLite snapshot via Python backup() API ---
SNAPSHOT="$TMP_DIR/index_${TIMESTAMP}.db"
log "Creating safe snapshot: $SNAPSHOT"

python3 - "$DB_PATH" "$SNAPSHOT" <<'PYEOF'
import sqlite3, sys
src_path, dst_path = sys.argv[1], sys.argv[2]
src = sqlite3.connect(f"file:{src_path}?mode=ro", uri=True)
dst = sqlite3.connect(dst_path)
src.backup(dst)
dst.close()
src.close()
print("snapshot OK")
PYEOF

if [ ! -f "$SNAPSHOT" ]; then
    log "ERROR: Snapshot failed — $SNAPSHOT not created"
    exit 1
fi

DB_SIZE=$(stat -c%s "$SNAPSHOT")
log "Snapshot created: ${DB_SIZE} bytes"

# --- 2. Compress ---
GZ_PATH="${SNAPSHOT}.gz"
log "Compressing to $GZ_PATH"
gzip -9 -c "$SNAPSHOT" > "$GZ_PATH"
GZ_SIZE=$(stat -c%s "$GZ_PATH")
log "Compressed: ${GZ_SIZE} bytes"

# --- 3. Upload to S3 ---
S3_KEY="s3://${S3_BUCKET}/${S3_PREFIX}/index_${DATESTAMP}.db.gz"
log "Uploading to $S3_KEY"

if AWS_PROFILE=oc-cassi aws s3 cp "$GZ_PATH" "$S3_KEY" --region us-east-2 >> "$LOG" 2>&1; then
    log "Upload complete: $S3_KEY"
else
    log "ERROR: S3 upload failed"
    rm -f "$SNAPSHOT" "$GZ_PATH"
    exit 1
fi

# --- 4. Cleanup local temp files ---
rm -f "$SNAPSHOT" "$GZ_PATH"
log "Temp files cleaned up"

# --- 5. Retention: keep last 30 days in S3 ---
log "Pruning S3 backups older than 30 days..."
CUTOFF=$(date -d '30 days ago' +%Y-%m-%d --utc)
AWS_PROFILE=oc-cassi aws s3api list-objects-v2 \
    --bucket "$S3_BUCKET" \
    --prefix "${S3_PREFIX}/" \
    --region us-east-2 \
    --query "Contents[?LastModified<='${CUTOFF}'].Key" \
    --output text 2>/dev/null | tr '\t' '\n' | while read -r old_key; do
        [ -n "$old_key" ] && {
            AWS_PROFILE=oc-cassi aws s3 rm "s3://${S3_BUCKET}/${old_key}" --region us-east-2 >> "$LOG" 2>&1
            log "Deleted old backup: $old_key"
        }
    done

log "=== Backup complete ==="