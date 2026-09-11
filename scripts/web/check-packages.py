#!/usr/bin/env python3
import argparse
import json
import re
import subprocess
import sys
from datetime import datetime

# Map display names to npm package names
ALIAS_TO_NPM = {
    "jquery": "jquery",
    "jquery ui": "jquery-ui",
    "jquery-ui": "jquery-ui",
    "jqueryui": "jquery-ui",
    "react": "react",
    "react-dom": "react-dom",
    "vue": "vue",
    "angular": "angular",  # angular.js 1.x
    "bootstrap": "bootstrap",
}

MD_HEADER_CANON = ["url", "package", "detected version", "latest npm version", "status", "evidence"]

SEMVER_RE = re.compile(r"^\s*v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?\s*$")

def npm_view_json(args, verbose=False):
    try:
        if verbose:
            print("[INFO] npm", " ".join(args))
        r = subprocess.run(["npm"] + args, capture_output=True, text=True, check=True)
        return json.loads(r.stdout)
    except Exception as e:
        if verbose:
            print(f"[WARN] npm {' '.join(args)} failed: {e}")
        return None

def npm_latest_version(pkg, verbose=False):
    return npm_view_json(["view", pkg, "version", "--json"], verbose=verbose)

def npm_time_map(pkg, verbose=False):
    # Returns dict {version: ISO8601 date}; includes "created"/"modified" keys we will ignore.
    return npm_view_json(["view", pkg, "time", "--json"], verbose=verbose)

def semver_parts(v):
    m = SEMVER_RE.match(v or "")
    return tuple(int(x) for x in m.groups()) if m else None

def bump_type(installed, latest):
    a = semver_parts(installed)
    b = semver_parts(latest)
    if not a or not b:
        return "unknown"
    if a == b:
        return "none"
    if a[0] != b[0]:
        return "major"
    if a[1] != b[1]:
        return "minor"
    if a[2] != b[2]:
        return "patch"
    return "unknown"

def out_of_support_since(detected_version, time_map, verbose=False):
    """
    Heuristic: a version is "out of support" on the publish date of the first later stable release.
    Returns YYYY-MM-DD string or "" if not out of support (i.e., it's the latest) or not found.
    """
    if not time_map or not detected_version:
        return ""
    # Build list of (version, date) for semver-looking versions only
    entries = []
    for v, iso in time_map.items():
        if v in ("created", "modified"):
            continue
        if not SEMVER_RE.match(v):
            continue  # skip pre-releases or non-semver tags
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        except Exception:
            continue
        entries.append((v, dt))
    if not entries:
        return ""

    # Sort chronologically by publish date
    entries.sort(key=lambda x: x[1])

    # Find detected version publish time
    detected_dt = None
    for v, dt in entries:
        if v == detected_version:
            detected_dt = dt
            break
    if not detected_dt:
        return ""

    # Find the first version published AFTER detected_dt
    for v, dt in entries:
        if dt > detected_dt:
            return dt.date().isoformat()

    # No later version published -> still current (no out-of-support date)
    return ""

def normalize_pkg_name(display_name):
    key = re.sub(r"\s+", " ", (display_name or "")).strip().lower()
    return ALIAS_TO_NPM.get(key, key)

def find_markdown_table(lines):
    """
    Find the start index, header, and alignment of the expected table.
    Returns (start_idx, header_line, align_line) or (None, None, None).
    """
    for i in range(len(lines)):
        ln = lines[i].strip()
        if not ln.startswith("|"):
            continue
        headers = [c.strip().lower() for c in ln.strip("|").split("|")]
        if headers == MD_HEADER_CANON:
            # Alignment line is next (optional but recommended)
            align_line = lines[i+1] if i+1 < len(lines) else ""
            return i, lines[i], align_line
    return None, None, None

def parse_rows(lines, start_idx):
    """
    Parse table rows after header/alignment rows until a non-table line.
    Returns list of rows (list of strings per cell) and the index after the table.
    """
    rows = []
    i = start_idx + 1
    # Skip alignment row if present
    if i < len(lines) and re.match(r"^\|\s*[:-]+", lines[i].strip()):
        i += 1
    while i < len(lines):
        ln = lines[i]
        if not ln.strip().startswith("|"):
            break
        cells = [c for c in ln.strip().strip("|").split("|")]
        # Pad or trim to 6 cells
        if len(cells) < 6:
            cells += [""] * (6 - len(cells))
        elif len(cells) > 6:
            cells = cells[:6]
        rows.append([c.strip() for c in cells])
        i += 1
    return rows, i

def format_row(cells):
    return "| " + " | ".join(cells) + " |"

def main():
    ap = argparse.ArgumentParser(description="Update packages.md with latest npm versions and out-of-support dates")
    ap.add_argument("-p", "--packages-md", required=True, help="Input packages.md in 6-column format")
    ap.add_argument("-o", "--output", required=True, help="Output markdown file")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    args = ap.parse_args()

    # Read file
    try:
        with open(args.packages_md, "r", encoding="utf-8", errors="ignore") as f:
            lines = [ln.rstrip("\n") for ln in f]
    except Exception as e:
        print(f"[ERROR] Could not read {args.packages_md}: {e}", file=sys.stderr)
        sys.exit(1)

    start_idx, header_line, align_line = find_markdown_table(lines)
    if start_idx is None:
        print("[ERROR] Could not find the expected header row:", file=sys.stderr)
        print("| URL | Package | Detected Version | Latest NPM Version | Status | Evidence |", file=sys.stderr)
        sys.exit(1)

    rows, end_idx = parse_rows(lines, start_idx)

    updated = []
    for row in rows:
        url, pkg_disp, detected, latest_cell, status_cell, evidence = row
        pkg = normalize_pkg_name(pkg_disp)
        detected = detected.strip()

        if args.verbose:
            print(f"[INFO] Processing {pkg_disp} (npm: {pkg}), detected {detected or 'N/A'}")

        latest = npm_latest_version(pkg, verbose=args.verbose)
        time_map = npm_time_map(pkg, verbose=args.verbose)

        # Determine status + out-of-support date
        status = "unknown"
        latest_str = latest if isinstance(latest, str) else ""
        if latest_str:
            if detected and detected == latest_str:
                status = "up-to-date"
                oos = ""
            elif detected:
                kind = bump_type(detected, latest_str)
                oos = out_of_support_since(detected, time_map, verbose=args.verbose)
                if oos:
                    status = f"outdated ({kind}), out of support since {oos}"
                else:
                    status = f"outdated ({kind})"
            else:
                status = "unknown"
        else:
            status = "unknown"

        # Write back: keep URL and Evidence as provided; update Latest + Status
        updated.append([
            url,
            pkg_disp,
            detected,
            latest_str or latest_cell,
            status,
            evidence
        ])

    # Rebuild file content: keep everything before header, replace the table block, keep everything after
    out_lines = []
    out_lines.extend(lines[:start_idx])
    out_lines.append(header_line)
    # Keep original alignment line if present, else a sensible default
    if re.match(r"^\|\s*[:-]+", align_line.strip() if align_line else ""):
        out_lines.append(align_line)
    else:
        out_lines.append("| :-: | :-------: | :--------------: | :----------------: | :----: | :------: |")
    for cells in updated:
        out_lines.append(format_row(cells))
    out_lines.extend(lines[end_idx:])

    # Print to console
    for ln in out_lines:
        print(ln)

    # Write to file
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(out_lines) + "\n")
        print(f"\n[INFO] Results saved to {args.output}")
    except Exception as e:
        print(f"[ERROR] Could not write {args.output}: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

