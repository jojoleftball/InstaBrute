#!/bin/bash
TOR_DIR="$PREFIX/etc/tor/multitor"  # Termux path
mkdir -p "$TOR_DIR" /data/data/com.termux/files/usr/var/lib/{tor1,tor2,tor3,tor4,tor5}

# Create configs
for i in {1..5}; do
    port=$((9050 + (i-1)*2))
    cat > "$TOR_DIR/tor${i}.conf" << EOF
SocksPort $port
DataDirectory /data/data/com.termux/files/usr/var/lib/tor$i
EOF
done

echo "Starting 5 Tor instances..."
for i in {1..5}; do
    tor -f "$TOR_DIR/tor${i}.conf" &>/dev/null &
    sleep 3
done
echo "Tor ready! Ports: 9050,9052,9054,9056,9058"
# Kill with pkill tor