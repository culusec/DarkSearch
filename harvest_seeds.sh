#!/bin/bash
# DarkSearch seed harvester — uses OnionClaw to find new .onion URLs
# Runs every 30 min via cron. Feeds the crawler queue.

LOG="/opt/darkweb/logs/seed_harvest.log"
QUEUE="/opt/darkweb/queue.txt"
SICRY="/opt/threat_intel/scripts/sicry.py"

# Rotate through 4 keyword batches based on hour
HOUR=$(date +%H)
case $((HOUR % 24)) in
    0|1|2|3|4|5)   TERMS=("ransomware leak site onion 2026" "darknet market forum new" "stolen database dump onion" "initial access broker 2026" "cve exploit zero day" "new ransomware group 2026" "leaked credentials database") ;;
    6|7|8|9|10|11)  TERMS=("darknet hosting service onion" "encrypted email provider onion" "hacking forum community 2026" "crypto drainer script new" "malware loader botnet 2026" "fresh onion links directory" "darknet marketplace 2026") ;;
    12|13|14|15|16|17) TERMS=("stolen data marketplace 2026" "botnet c2 panel onion" "carding cvv dumps 2026" "ransomware data leak site" "hacked database for sale" "new onion service 2026" "cybercrime forum onion") ;;
    18|19|20|21|22|23) TERMS=("cloud credential leak 2026" "wallet cracker tool new" "supply chain exploit 2026" "ransomware affiliate program" "stealer logs marketplace" "sim swapping service onion" "bank login shop onion") ;;
esac

TOTAL=0
HITS=0

echo "$(date): Starting harvest (batch: $(date +%H)h)" >> "$LOG"

for term in "${TERMS[@]}"; do
    # Skip if we already have enough seeds queued
    if [ -f "$QUEUE" ]; then
        QUEUED=$(wc -l < "$QUEUE" 2>/dev/null || echo 0)
        if [ "$QUEUED" -gt 200 ]; then
            echo "  Queue has $QUEUED URLs — skipping harvest" >> "$LOG"
            break
        fi
    fi
    
    # Use Python + sicry to search (depth=30 for more fresh URLs)
    added=$(python3 -c "
import sys, importlib.util
spec = importlib.util.spec_from_file_location('sicry', '$SICRY')
sicry = importlib.util.module_from_spec(spec)
sys.modules['sicry'] = sicry
spec.loader.exec_module(sicry)

existing = set()
try:
    with open('$QUEUE') as f:
        existing = set(l.strip() for l in f)
except: pass

crawled = set()
try:
    with open('/opt/darkweb/crawled.txt') as f:
        crawled = set(l.strip() for l in f)
except: pass

count = 0
try:
    results = sicry.search('$term', max_results=30, engines=['Ahmia-clearnet', 'Tor66', 'Excavator', 'OnionLand', 'TheDeepSearches', 'Ahmia'])
    for r in results:
        url = r.get('url', '') or r.get('link', '')
        if '.onion' in url and url not in existing and url not in crawled:
            existing.add(url)
            with open('$QUEUE', 'a') as f:
                f.write(url + '\\n')
            count += 1
except Exception as e:
    print(f'ERROR:{e}', file=sys.stderr)

print(count)
" 2>/dev/null)
    
    if [ -n "$added" ] && [ "$added" -gt 0 ] 2>/dev/null; then
        echo "  +${added} URLs from \"$term\"" >> "$LOG"
        TOTAL=$((TOTAL + added))
        HITS=$((HITS + 1))
    fi
    
    sleep 3  # Be gentle on engines
done

echo "  Total: +${TOTAL} URLs from ${HITS}/${#TERMS[@]} searches (queue: $(wc -l < "$QUEUE" 2>/dev/null || echo 0))" >> "$LOG"

# If crawler is dead, restart it
if ! pgrep -f "crawler.py" > /dev/null 2>&1; then
    echo "  Crawler was dead — restarting" >> "$LOG"
    cd /opt/darkweb && nohup python3 -u crawler.py >> logs/crawler.log 2>&1 &
fi
