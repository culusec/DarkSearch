#!/bin/bash
# DarkSearch launcher — starts Tor hidden service, waits for it, then launches Flask
set -e
DRIVE="/mnt/darkweb"

# Kill any stale processes
pkill -f "tor -f $DRIVE/torrc" 2>/dev/null || true
sleep 1

# Start darkweb Tor
tor -f "$DRIVE/torrc" --pidfile "$DRIVE/tor.pid" --runasdaemon 1

# Wait for hidden service hostname
for i in $(seq 1 30); do
    if [ -f "$DRIVE/tor-data/hidden_service/hostname" ]; then
        echo "Tor hidden service ready: $(cat $DRIVE/tor-data/hidden_service/hostname)"
        break
    fi
    sleep 2
done

# Launch Flask
exec python3 "$DRIVE/server.py"
