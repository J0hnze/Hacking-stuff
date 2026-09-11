#!/usr/bin/env python3

import os
import sys
import argparse
import csv
from tabulate import tabulate
import webbrowser

def load_dorks(dork_file):
    if not os.path.isfile(dork_file):
        print(f"[!] Dork file not found: {dork_file}")
        sys.exit(1)
    with open(dork_file, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def generate_dorks(domain, dork_list):
    dorks = []
    for dork in dork_list:
        query = f"site:{domain} {dork}"
        dorks.append(query)
    return dorks

def write_dorks_to_csv(domain, dorks):
    filename = f"{domain}.csv"
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Dork Query'])
        for dork in dorks:
            writer.writerow([dork])
    print(f"[+] Saved dorks to {filename}")

def display_dorks_ascii(domain, dorks):
    table = [[query] for query in dorks]
    print(f"\n[+] Dorks for {domain}:")
    print(tabulate(table, headers=['Dork Query'], tablefmt='grid'))

def run_dorks_in_browser(dorks):
    for query in dorks:
        url = f"https://duckduckgo.com/?q={query.replace(' ', '+')}"
        webbrowser.open_new_tab(url)

def process_targets_file(targets_file, output_mode, dork_file):
    if not os.path.isfile(targets_file):
        print(f"[!] File not found: {targets_file}")
        return

    dork_list = load_dorks(dork_file)

    with open(targets_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    for domain in domains:
        dorks = generate_dorks(domain, dork_list)
        if output_mode == 1:
            display_dorks_ascii(domain, dorks)
        elif output_mode == 2:
            write_dorks_to_csv(domain, dorks)
        elif output_mode == 3:
            run_dorks_in_browser(dorks)
        else:
            print("[!] Invalid output mode. Use 1 for screen, 2 for CSV file, or 3 to run in browser.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate and run search engine dorks for domains.")
    parser.add_argument('-t', '--targets', required=True, help='Path to the targets file (one domain per line)')
    parser.add_argument('-d', '--dorks', required=True, help='Path to the dorks file (one dork pattern per line)')
    parser.add_argument('-o', '--output', type=int, choices=[1, 2, 3], default=1,
                        help='Output mode: 1 for screen, 2 for CSV files, 3 to open in browser (default: 1)')

    args = parser.parse_args()

    process_targets_file(args.targets, args.output, args.dorks)

