#!/bin/bash
# Colors
red="\033[1;31m"
green="\033[1;32m"
yellow="\033[1;33m"
cyan="\033[1;36m"
nc="\e[0m"

# Hacker Banner
echo -e "$red"
echo "  ____            _          ____            _       ___       "
echo " | __ ) _   _ ___| |__   ___| __ ) _ __ __ _| |__   |_ _|_ __  "
echo " |  _ \\| | | / __| '_ \\ / __|  _ \\| '__/ _\` | '_ \\   | || '_ \\ "
echo " | |_) | |_| \\__ \\ |_) | (__| |_) | | | (_| | |_) |  | || | | |"
echo " |____/ \\__,_/|___/_.__/ \\___|____/|_|  \\__,_|_.__/  |___|_| |_|"
echo -e "           $cyan InstaBrutePro v1.0 - by Soly $nc"
echo -e "$yellow[*] Elite Instagram Brute-Forcer for Ethical Pentesting Only$nc"
echo -e "$red[!] Legal: Consent REQUIRED. Unauthorized use ILLEGAL.$nc\n"

echo -e "$cyan[*] Initializing InstaBrutePro Setup...$nc"
sleep 1

# Install dependencies
echo -e "$yellow[*] Installing Termux dependencies...$nc"
pkg update -y && pkg install tor python curl openssl git -y
echo -e "$green[+] Dependencies installed! [$green✓$nc]$nc"

# Install Python packages
echo -e "$yellow[*] Installing Python requirements...$nc"
pip install -r requirements.txt
echo -e "$green[+] Python packages ready! [$green✓$nc]$nc"

# Create directories
echo -e "$yellow[*] Setting up directories...$nc"
mkdir -p wordlists proxies config hits
echo -e "$green[+] Directories created! [$green✓$nc]$nc"

# Download sample wordlist
echo -e "$yellow[*] Downloading 10M wordlist (rockyou sample)...$nc"
curl -L -o wordlists/rockyou_sample.txt https://raw.githubusercontent.com/0xfff0800/Brute-force-Instagram-2025/master/wordlist.txt
if [ -f wordlists/rockyou_sample.txt ]; then
    echo -e "$green[+] Wordlist downloaded! [$green✓$nc]$nc"
else
    echo -e "$red[!] Wordlist download failed! Check URL or network.$nc"
    exit 1
fi

# Fetch proxies
echo -e "$yellow[*] Fetching SOCKS5 proxies...$nc"
curl -s https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all > proxies/free_proxies.txt
if [ -s proxies/free_proxies.txt ]; then
    echo -e "$green[+] Proxies fetched! [$green✓$nc]$nc"
else
    echo -e "$red[!] Proxy fetch failed! Using Tor proxies as fallback.$nc"
    cat > proxies/free_proxies.txt << EOF
socks5://127.0.0.1:9050
socks5://127.0.0.1:9052
socks5://127.0.0.1:9054
socks5://127.0.0.1:9056
socks5://127.0.0.1:9058
EOF
    echo -e "$green[+] Tor proxies added to free_proxies.txt! [$green✓$nc]$nc"
fi

# Create config
echo -e "$yellow[*] Generating configuration...$nc"
cat > config/instabrute_config.json << EOF
{"threads": 100, "delay": 0.1, "tor_ports": [9050,9052,9054,9056,9058]}
EOF
echo -e "$green[+] Config created! [$green✓$nc]$nc"

# Make multitor.sh executable
chmod +x multitor.sh
echo -e "$green[+] multitor.sh ready! [$green✓$nc]$nc"

echo -e "$cyan[*] InstaBrutePro Setup Complete! [$green✓$nc]$nc"
echo -e "$yellow[*] Next Steps:$nc"
echo -e "$yellow    1. Start Tor: ./multitor.sh$nc"
echo -e "$yellow    2. Validate: python validate_user.py <username>$nc"
echo -e "$yellow    3. Brute: python brute.py -u <username> -w wordlists/rockyou_sample.txt -t 100$nc"
echo -e "$red[!] Test on YOUR account with consent only!$nc"