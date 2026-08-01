#!/bin/bash
# DarkSearch launcher — uses system Tor, launches Flask web UI
set -e
DRIVE="/opt/darkweb"

# System Tor is managed by systemd — verify it's running
if ! systemctl is-active --quiet tor 2>/dev/null; then
    echo "Starting system Tor..."
    sudo systemctl start tor
    sleep 3
fi

echo "Tor SOCKS proxy: 127.0.0.1:9050 (system tor)"

# Launch Flask
cd "$DRIVE"
exec python3 server.py
