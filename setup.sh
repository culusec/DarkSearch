#!/bin/bash
# DarkSearch — EC2 setup script (no external drive)
# Run once on a fresh instance.
# Usage: bash /opt/darkweb/setup.sh

set -e
DRIVE="/opt/darkweb"
echo "DarkSearch Setup — $(date)"
echo "=========================="

# 1. Check directory
if [ ! -d "$DRIVE" ]; then
    echo "ERROR: $DRIVE not found."
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
pip3 install --break-system-packages scrapy flask requests "beautifulsoup4>=4.12" pysocks psycopg2-binary 2>/dev/null

# 4. Tor config — uses system tor, not a separate instance
echo "[3/4] Tor already configured via systemd — skipping separate tor instance"
echo "  System Tor SOCKS proxy: 127.0.0.1:9050"

# 5. Ensure directories exist
echo "[4/4] Creating directories..."
mkdir -p "$DRIVE/logs"

echo ""
echo "Setup complete."
echo "Start crawler: cd $DRIVE && python3 crawler.py"
echo "Start web UI:  cd $DRIVE && python3 server.py"

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
