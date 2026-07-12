#!/bin/bash
COUNT=$(pgrep -cf crawler.py)
if [ "$COUNT" -eq 0 ]; then
    echo "$(date): Crawler dead — restarting" >> /mnt/darkweb/logs/crawler_watchdog.log
    cd /mnt/darkweb && nohup python3 -u crawler.py >> logs/crawler.log 2>&1 &
else
    # Also check if it's stuck — no new pages in 10+ minutes
    DB_AGE=$(stat -c %Y /mnt/darkweb/index.db 2>/dev/null)
    NOW=$(date +%s)
    if [ -n "$DB_AGE" ] && [ $((NOW - DB_AGE)) -gt 600 ]; then
        echo "$(date): Crawler may be stuck (DB unchanged for $(((NOW-DB_AGE)/60)) min) — restarting" >> /mnt/darkweb/logs/crawler_watchdog.log
        pkill -f crawler.py
        sleep 2
        cd /mnt/darkweb && nohup python3 -u crawler.py >> logs/crawler.log 2>&1 &
    fi
fi
