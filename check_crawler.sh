#!/bin/bash
# DarkSearch crawler watchdog — ensures the crawler daemon stays alive
# Checks every 60 seconds. If dead, restarts. If stuck, kills + restarts.

DB="/mnt/darkweb/index.db"
LOG="/mnt/darkweb/logs/crawler_watchdog.log"
CRAWLER_LOG="/mnt/darkweb/logs/crawler.log"
LOCK="/tmp/darksearch_crawler.lock"

# Prevent overlapping watchdog instances
exec 200>"$LOCK"
flock -n 200 || exit 0

COUNT=$(pgrep -cf crawler.py)

if [ "$COUNT" -eq 0 ]; then
    echo "$(date): Crawler daemon not running — starting" >> "$LOG"
    cd /mnt/darkweb && nohup python3 -u crawler.py >> logs/crawler.log 2>&1 &
    exit 0
fi

# Check if crawler is stuck: DB unchanged for >15 minutes, AND no log activity for >10 min
if [ -f "$DB" ]; then
    DB_AGE=$(stat -c %Y "$DB" 2>/dev/null)
    NOW=$(date +%s)
    DB_STALE=$((NOW - DB_AGE))
    
    if [ "$DB_STALE" -gt 900 ]; then
        # Also check if the crawler log has recent activity
        if [ -f "$CRAWLER_LOG" ]; then
            LOG_AGE=$(stat -c %Y "$CRAWLER_LOG" 2>/dev/null)
            LOG_STALE=$((NOW - LOG_AGE))
            if [ "$LOG_STALE" -gt 600 ]; then
                echo "$(date): Crawler stuck (DB unchanged ${DB_STALE}s, no log ${LOG_STALE}s) — restarting" >> "$LOG"
                pkill -f crawler.py
                sleep 3
                cd /mnt/darkweb && nohup python3 -u crawler.py >> logs/crawler.log 2>&1 &
            fi
        fi
    fi
fi
