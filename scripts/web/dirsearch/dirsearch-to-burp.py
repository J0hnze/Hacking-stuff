#!/usr/bin/env python3
"""
Replay dirsearch results through Burp proxy.

Reads dirsearch output and sends each discovered URL through Burp
so they appear in the sitemap and proxy history without the 403/404 noise.

Usage:
    python3 dirsearch-to-burp.py -f dirsearch-results.md
    python3 dirsearch-to-burp.py -f dirsearch-results.md --proxy 127.0.0.1:8080
    python3 dirsearch-to-burp.py -f dirsearch-results.md --status 200,301,302
    python3 dirsearch-to-burp.py -f dirsearch-results.md --delay 0.5
"""

import argparse
import re
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_dirsearch_output(filepath, status_filter=None):
    urls = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # dirsearch markdown format: "200   1234B   https://example.com/path"
            # or plain text: "200     1KB  /path"
            # or CSV-like: "200,1234,https://example.com/path"

            # Try markdown/text format first
            match = re.match(
                r"(\d{3})\s+[\d.]+[KMB]*\s+(https?://\S+)", line
            )
            if not match:
                # Try format with just status and path
                match = re.match(r"(\d{3})\s+\S+\s+(\S+)", line)
            if not match:
                # Try bare URL
                if line.startswith("http"):
                    urls.append({"status": None, "url": line})
                    continue
                continue

            status = int(match.group(1))
            url = match.group(2)

            if status_filter and status not in status_filter:
                continue

            urls.append({"status": status, "url": url})

    return urls


def send_through_burp(urls, proxy_host, proxy_port, delay, user_agent):
    proxies = {
        "http": f"http://{proxy_host}:{proxy_port}",
        "https": f"http://{proxy_host}:{proxy_port}",
    }

    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    total = len(urls)
    success = 0
    failed = 0

    print(f"[*] Sending {total} URLs through {proxy_host}:{proxy_port}")
    print(f"[*] User-Agent: {user_agent}")
    if delay:
        print(f"[*] Delay: {delay}s between requests")
    print()

    for i, entry in enumerate(urls, 1):
        url = entry["url"]
        orig_status = entry["status"]
        status_str = f" (dirsearch: {orig_status})" if orig_status else ""

        try:
            resp = requests.get(
                url,
                headers=headers,
                proxies=proxies,
                verify=False,
                timeout=15,
                allow_redirects=False,
            )
            print(
                f"  [{i}/{total}] {resp.status_code} | {len(resp.content):>6}B | {url}{status_str}"
            )
            success += 1

        except requests.exceptions.ProxyError:
            print(f"  [{i}/{total}] PROXY ERROR | {url} -- is Burp running?")
            failed += 1
        except requests.exceptions.RequestException as e:
            print(f"  [{i}/{total}] ERROR | {url} -- {e}")
            failed += 1

        if delay and i < total:
            time.sleep(delay)

    print()
    print(f"[+] Done: {success} sent, {failed} failed, {total} total")


def main():
    parser = argparse.ArgumentParser(
        description="Replay dirsearch results through Burp proxy"
    )
    parser.add_argument(
        "-f", "--file", required=True,
        help="Path to dirsearch output file"
    )
    parser.add_argument(
        "--proxy", default="127.0.0.1:8080",
        help="Burp proxy address (default: 127.0.0.1:8080)"
    )
    parser.add_argument(
        "--status", default=None,
        help="Only replay these status codes (comma-separated, e.g. 200,301,302)"
    )
    parser.add_argument(
        "--delay", type=float, default=0,
        help="Delay in seconds between requests (default: 0)"
    )
    parser.add_argument(
        "--user-agent", default="DirReplay",
        help="User-Agent header (default: DirReplay)"
    )
    args = parser.parse_args()

    proxy_parts = args.proxy.split(":")
    proxy_host = proxy_parts[0]
    proxy_port = int(proxy_parts[1]) if len(proxy_parts) > 1 else 8080

    status_filter = None
    if args.status:
        status_filter = set(int(s.strip()) for s in args.status.split(","))

    urls = parse_dirsearch_output(args.file, status_filter)

    if not urls:
        print("[-] No URLs found in the file (check format or status filter)")
        sys.exit(1)

    print(f"[+] Parsed {len(urls)} URLs from {args.file}")
    if status_filter:
        print(f"[+] Filtered to status codes: {status_filter}")

    send_through_burp(urls, proxy_host, proxy_port, args.delay, args.user_agent)


if __name__ == "__main__":
    main()
