#!/usr/bin/env python3
# dork_scraper_stage2_selenium.py

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from bs4 import BeautifulSoup
import argparse
import os
import time
import datetime
import pathlib

SEARCH_ENGINES = {
    'google': "https://www.google.com/search?q=",
    'duckduckgo': "https://duckduckgo.com/?q=",
    'bing': "https://www.bing.com/search?q="
}

def read_lines_from_file(path):
    if not path or not path.endswith('.txt') or not os.path.isfile(path):
        print(f"[!] Invalid or missing file: {path}")
        return []

    with open(path, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("###")]

def run_selenium_scraper(target_file, dork_file, engine, sleep_timer):
    targets = read_lines_from_file(target_file)
    dorks = read_lines_from_file(dork_file)

    if not targets or not dorks:
        print("[!] No targets or dorks loaded.")
        return

    output_dir = pathlib.Path("temp")
    output_dir.mkdir(parents=True, exist_ok=True)

    options = Options()
    # options.add_argument("--headless")  # Disable headless for visual debugging
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1200,800")

    print("[+] Launching Chromium browser...")
    service = Service(executable_path="/usr/bin/chromedriver")

    for idx, target in enumerate(targets):
        driver = webdriver.Chrome(service=service, options=options)
        print(f"\n=== Target: {target} ===")

        for dork in dorks:
            query = f"site:{target} {dork}"
            search_url = SEARCH_ENGINES[engine] + query.replace(' ', '+')
            print(f"[*] Navigating to: {search_url}")

            driver.execute_script(f"window.open('{search_url}');")
            driver.switch_to.window(driver.window_handles[-1])
            print("[*] Please interact with the browser if needed (CAPTCHA, consent banners).")
            time.sleep(sleep_timer)

            # Save the page source
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"{target}_{dork.replace(':', '-')}_{timestamp}.html"
            filepath = output_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(driver.page_source)

        print("[*] Dorks for current target complete. Please close the browser window to proceed to the next target...")
        while len(driver.window_handles) > 0:
            time.sleep(2)

        driver.quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Use Selenium to scrape search engines using dork queries.")
    parser.add_argument('-t', '--targets', default='example-targets.txt', help='Path to targets file (default: example-targets.txt)')
    parser.add_argument('-d', '--dorks', default='example-dorks.txt', help='Path to dorks file (default: example-dorks.txt)')
    parser.add_argument('-e', '--engine', type=str, choices=['google', 'duckduckgo', 'bing'], default='google', help='Search engine to use')
    parser.add_argument('-s', '--sleep', type=int, default=10, help='Time in seconds to wait after loading each search (default: 10)')
    args = parser.parse_args()

    run_selenium_scraper(args.targets, args.dorks, args.engine, args.sleep)
