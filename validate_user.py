#!/usr/bin/env python3
import requests
import sys

def validate(username):
    ua = "Instagram 350.0.0.21.114 Android (34/14; 560dpi; 1440x3120; samsung; SM-S928B; dm3q; exynos5400; en_US; 350000000000000)"
    try:
        resp = requests.get(
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers={"User-Agent": ua},
            timeout=10
        )
        if resp.status_code == 200 and '"user"' in resp.text:
            print(f"[+] Valid: {username} (Public or Private)")
            return True
        else:
            print(f"[-] Invalid: {username} (Does not exist or blocked)")
            return False
    except requests.RequestException as e:
        print(f"[!] Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_user.py <username>")
        sys.exit(1)
    validate(sys.argv[1])