#!/bin/bash
# DarkSearch — portable setup script
# Run this once when moving the drive to a new machine.
# Usage: bash /mnt/darkweb/setup.sh

set -e
DRIVE="/mnt/darkweb"
echo "DarkSearch Setup — $(date)"
echo "=========================="

# 1. Check drive
if [ ! -d "$DRIVE" ]; then
    echo "ERROR: $DRIVE not found. Is the drive mounted?"
    exit 1
fi

# 2. Install system dependencies
echo "[1/4] Installing system packages..."
if command -v apt &>/dev/null; then
    sudo apt update -qq
    sudo apt install -y -qq tor python3 python3-pip 2>/dev/null
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm tor python python-pip 2>/dev/null
fi

# 3. Install Python dependencies
echo "[2/4] Installing Python packages..."
pip3 install --break-system-packages scrapy flask requests "beautifulsoup4>=4.12" pysocks 2>/dev/null

# 4. Check Tor config
echo "[3/4] Configuring Tor..."
# Kill any old darkweb tor instance
pkill -f "tor -f $DRIVE/torrc" 2>/dev/null || true
sleep 1

# Ensure directories exist
mkdir -p "$DRIVE/tor-data/hidden_service" "$DRIVE/logs"

# Start Tor
tor -f "$DRIVE/torrc" --pidfile "$DRIVE/tor.pid" --runasdaemon 1

# Wait for hidden service
echo "  Waiting for Tor hidden service..."
for i in $(seq 1 30); do
    if [ -f "$DRIVE/tor-data/hidden_service/hostname" ]; then
        echo "  .onion: $(cat $DRIVE/tor-data/hidden_service/hostname)"
        break
    fi
    sleep 2
done

# 5. Start services
echo "[4/4] Starting DarkSearch..."
# Kill old processes
pkill -f "$DRIVE/server.py" 2>/dev/null || true
sleep 1

# Start Flask
cd "$DRIVE" && nohup python3 server.py > logs/server.log 2>&1 &

sleep 2

echo ""
echo "=========================="
echo "DarkSearch is running!"
echo "  Local:   http://127.0.0.1:8082/"
echo "  Tor:     http://$(cat $DRIVE/tor-data/hidden_service/hostname 2>/dev/null || echo 'starting...')"
echo ""
echo "  Start crawl: cd $DRIVE && nohup python3 -u crawler.py > logs/crawler.log 2>&1 &"
echo "  Check index: sqlite3 $DRIVE/index.db 'SELECT COUNT(*) FROM pages'"
echo "=========================="
