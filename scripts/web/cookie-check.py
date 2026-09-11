#!/usr/bin/env python3

import requests
import argparse
from http.cookies import SimpleCookie
import urllib3

# Disable SSL warnings (Burp proxy MITM)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BURP_PROXY = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

HEADERS = {
    "User-Agent": "cookie-audit/1.0",
    "X-Cookie-Check": "true"
}


def parse_set_cookie(headers):
    cookies = []

    # Get all Set-Cookie headers properly
    raw_cookies = []
    try:
        raw_cookies = headers.getlist("Set-Cookie")
    except AttributeError:
        # Fallback if getlist not available
        if "Set-Cookie" in headers:
            raw_cookies = [headers.get("Set-Cookie")]

    for raw in raw_cookies:
        cookie = SimpleCookie()
        cookie.load(raw)

        for key, morsel in cookie.items():
            cookies.append({
                "name": key,
                "value": morsel.value,
                "secure": bool(morsel["secure"]),
                "httponly": bool(morsel["httponly"]),
                "samesite": morsel["samesite"] or None,
                "domain": morsel["domain"] or None,
                "path": morsel["path"] or None
            })

    return cookies


def analyze_cookies(cookies):
    findings = []

    for c in cookies:
        issues = []

        if not c["secure"]:
            issues.append("Missing Secure")

        if not c["httponly"]:
            issues.append("Missing HttpOnly")

        if not c["samesite"]:
            issues.append("Missing SameSite")

        findings.append({
            "cookie": c["name"],
            "issues": issues,
            "raw": c
        })

    return findings


def fetch_and_analyze(url):
    response = requests.get(
        url,
        headers=HEADERS,
        proxies=BURP_PROXY,
        verify=False,
        allow_redirects=True
    )

    cookies = parse_set_cookie(response.raw.headers)
    results = analyze_cookies(cookies)

    return results


def main():
    parser = argparse.ArgumentParser(description="Cookie Security Auditor (Burp Proxy Enabled)")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()

    results = fetch_and_analyze(args.url)

    for r in results:
        print(f"[+] Cookie: {r['cookie']}")
        if r["issues"]:
            for issue in r["issues"]:
                print(f"    - {issue}")
        else:
            print("    - No issues")


if __name__ == "__main__":
    main()
