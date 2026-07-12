#!/bin/bash
URL="https://ahmia.fi/static/onion-links.json"
OUT="/mnt/darkweb/logs/ahmia_check.log"
RESULT=$(curl -sL --max-time 15 -o /tmp/ahmia_links.json -w "%{http_code}" "$URL" 2>/dev/null)
COUNT=0
if [ "$RESULT" = "200" ]; then
    COUNT=$(python3 -c "import json; data=json.load(open('/tmp/ahmia_links.json')); print(len([u['url'] for u in data if 'url' in u]))" 2>/dev/null)
    if [ "$COUNT" -gt 100 ]; then
        python3 -c "
import json
data = json.load(open('/tmp/ahmia_links.json'))
urls = set()
with open('/mnt/darkweb/seeds.txt') as f:
    for line in f:
        urls.add(line.strip())
added = 0
for u in data:
    if 'url' in u and u['url'] not in urls:
        urls.add(u['url'])
        added += 1
with open('/mnt/darkweb/seeds.txt', 'w') as f:
    for u in sorted(urls):
        f.write(u + '\n')
# Also add to queue
with open('/mnt/darkweb/queue.txt') as f:
    queue = set(line.strip() for line in f if line.strip())
for u in data:
    if 'url' in u and u['url'] not in queue:
        queue.add(u['url'])
with open('/mnt/darkweb/queue.txt', 'w') as f:
    for u in sorted(queue):
        f.write(u + '\n')
print(f'Ahmia returned {len(data)} onions, added {added} new to seeds')
" 2>&1
    fi
    echo "$(date): HTTP $RESULT, $COUNT onions" >> "$OUT"
else
    echo "$(date): HTTP $RESULT (down)" >> "$OUT"
fi
