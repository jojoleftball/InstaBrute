#!/usr/bin/env python3
import requests
import sys

def validate(username):
    ua = "Instagram 350.0.0.21.114 Android (34/14; 560dpi; 1440x3120; samsung; SM-S928B; dm3q; exynos5400; en_US; 350000000000000)"
    resp = requests.get(f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}", headers={"User-Agent": ua})
    if '"is_private":false' in resp.text or '"user_id"' in resp.text:
        print(f"[+] Valid: {username}")
        return True
    print(f"[-] Invalid: {username}")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_user.py <username>")
    else:
        validate(sys.argv[1])