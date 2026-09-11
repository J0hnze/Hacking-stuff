#!/usr/bin/env python3
"""
generate_emails.py

Usage:
  python3 generate_emails.py names.txt -d example.com -iL -FL -F -o results.txt

Generates possible email addresses from a list of names using the following patterns:
  -iL : first initial + lastname   → j.smith@example.com
  -FL : first + lastname           → john.smith@example.com
  -F  : first only                 → john@example.com
"""

import argparse
import os
import re
import unicodedata

def normalize_token(s: str) -> str:
    s = s.strip()
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[^A-Za-z0-9'\-]", "", s)
    return s.lower()

def parse_name_line(line: str):
    line = line.strip()
    if not line:
        return None

    # Handle "Last, First" or "First Last"
    if ',' in line:
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 2:
            last = parts[0]
            first = parts[1].split()[0] if parts[1].split() else ''
        else:
            tokens = line.replace(',', ' ').split()
            first = tokens[0] if tokens else ''
            last = tokens[-1] if len(tokens) > 1 else ''
    else:
        tokens = line.split()
        if len(tokens) == 1:
            first = tokens[0]
            last = ''
        else:
            first = tokens[0]
            last = tokens[-1]

    f = normalize_token(first)
    l = normalize_token(last)
    return (f, l)

def generate_entries(names_path: str, domain: str, patterns):
    seen = set()
    entries = []

    with open(names_path, 'r', encoding='utf-8', errors='ignore') as fh:
        for raw in fh:
            parsed = parse_name_line(raw)
            if not parsed:
                continue
            first, last = parsed
            if not first:
                continue

            if "-iL" in patterns and last:
                email = f"{first[0]}.{last}@{domain}"
                if email not in seen:
                    seen.add(email)
                    entries.append(email)

            if "-FL" in patterns and last:
                email = f"{first}.{last}@{domain}"
                if email not in seen:
                    seen.add(email)
                    entries.append(email)

            if "-F" in patterns:
                email = f"{first}@{domain}"
                if email not in seen:
                    seen.add(email)
                    entries.append(email)

    return entries

def main():
    parser = argparse.ArgumentParser(
        description="Generate potential email addresses from names and domain."
    )
    parser.add_argument("names", help="Path to names.txt (one name per line)")
    parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g. example.com)")
    parser.add_argument("-o", "--output", help="Optional output file (default: print to stdout)")
    parser.add_argument("-iL", action="store_true", help="Use first-initial.lastname format (j.smith@domain)")
    parser.add_argument("-FL", action="store_true", help="Use first.lastname format (john.smith@domain)")
    parser.add_argument("-F", action="store_true", help="Use first format (john@domain)")
    args = parser.parse_args()

    if not os.path.isfile(args.names):
        print(f"[!] Names file not found: {args.names}")
        return

    if not (args.iL or args.FL or args.F):
        print("[!] You must specify at least one pattern: -iL, -FL, or -F")
        return

    domain = args.domain.strip().lower()
    domain = re.sub(r"^mailto:", "", domain)

    selected_patterns = []
    if args.iL: selected_patterns.append("-iL")
    if args.FL: selected_patterns.append("-FL")
    if args.F:  selected_patterns.append("-F")

    entries = generate_entries(args.names, domain, selected_patterns)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(entries) + ("\n" if entries else ""))
        print(f"[✓] Wrote {len(entries)} emails to {args.output}")
    else:
        for e in entries:
            print(e)

if __name__ == "__main__":
    main()
