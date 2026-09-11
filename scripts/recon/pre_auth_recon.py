#!/usr/bin/env python3
"""Pre-authentication reconnaissance - security headers, SSL/TLS, WAF detection, and technology fingerprinting."""

import argparse
import csv
import json
import re
import socket
import ssl
import sys
import warnings
from datetime import datetime, timezone
from urllib.parse import urlparse

import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning, module="ssl")


# --- Security Headers ---

EXPECTED_HEADERS = {
    "strict-transport-security": {
        "description": "HTTP Strict Transport Security",
        "recommended": "max-age=31536000; includeSubDomains; preload",
    },
    "x-frame-options": {
        "description": "Clickjacking Protection",
        "recommended": "DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "description": "MIME Sniffing Protection",
        "recommended": "nosniff",
    },
    "content-security-policy": {
        "description": "Content Security Policy",
        "recommended": "Restrictive policy",
    },
    "x-xss-protection": {
        "description": "XSS Filter (legacy)",
        "recommended": "0 (disabled, rely on CSP)",
    },
    "referrer-policy": {
        "description": "Referrer Policy",
        "recommended": "no-referrer or strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "description": "Permissions Policy",
        "recommended": "Restrict sensitive APIs",
    },
    "cache-control": {
        "description": "Cache Control",
        "recommended": "no-store for sensitive pages",
    },
    "x-permitted-cross-domain-policies": {
        "description": "Cross Domain Policy",
        "recommended": "none",
    },
    "cross-origin-opener-policy": {
        "description": "Cross-Origin Opener Policy",
        "recommended": "same-origin",
    },
    "cross-origin-resource-policy": {
        "description": "Cross-Origin Resource Policy",
        "recommended": "same-origin",
    },
    "cross-origin-embedder-policy": {
        "description": "Cross-Origin Embedder Policy",
        "recommended": "require-corp",
    },
}

INFORMATION_DISCLOSURE_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
]


def check_security_headers(url, timeout=15, verify_ssl=False, shcheck_file=None):
    """Check security headers on target URL. Uses shcheck output if available."""
    findings = []
    import subprocess
    import glob
    import os

    # Try to find existing shcheck output file
    if not shcheck_file:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        shcheck_files = glob.glob(os.path.join(parent_dir, "shcheck*"))
        if shcheck_files:
            shcheck_file = shcheck_files[0]

    shcheck_output = None

    # If we have a shcheck file, parse it
    if shcheck_file and os.path.isfile(shcheck_file):
        print(f"  {C.BLUE}[i] Using shcheck output: {os.path.basename(shcheck_file)}{C.RESET}")
        shcheck_output = _parse_shcheck_file(shcheck_file)
    else:
        # Try running shcheck live
        try:
            result = subprocess.run(
                ["shcheck", url],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout:
                shcheck_output = _parse_shcheck_output(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # If shcheck provided results, use them
    if shcheck_output and len(shcheck_output) > 0:
        findings.extend(shcheck_output)
    else:
        # Fall back to built-in header checks
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            print(f"[!] Error connecting to {url}: {e}")
            return []

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, info in EXPECTED_HEADERS.items():
            value = resp_headers.get(header)
            if value:
                status = "Present"
            else:
                status = "Missing"
                value = ""
            findings.append({
                "check": "Security Header",
                "item": info["description"],
                "status": status,
                "value": value,
                "recommendation": info["recommended"] if status == "Missing" else "",
            })

        for header in INFORMATION_DISCLOSURE_HEADERS:
            value = resp_headers.get(header)
            if value:
                findings.append({
                    "check": "Information Disclosure",
                    "item": f"Header: {header}",
                    "status": "Exposed",
                    "value": value,
                    "recommendation": "Remove or suppress version information",
                })

        # CSP Analysis
        csp_value = resp_headers.get("content-security-policy", "")
        if csp_value:
            findings.extend(analyse_csp(csp_value))

    return findings


def _parse_shcheck_file(filepath):
    """Parse shcheck output file (text format)."""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return _parse_shcheck_output(content)


def _parse_shcheck_output(output):
    """Parse shcheck stdout/text output into findings."""
    findings = []

    # shcheck output patterns:
    # [*] Header: value            (present)
    # [!] Missing: Header Name     (missing)
    # [ ] Header not present       (missing)
    # Header ...................... [ Present ]
    # Header ...................... [ Missing ]

    # Map shcheck header names to our descriptions
    header_name_map = {
        "x-frame-options": "Clickjacking Protection",
        "x-xss-protection": "XSS Filter (legacy)",
        "x-content-type-options": "MIME Sniffing Protection",
        "strict-transport-security": "HTTP Strict Transport Security",
        "content-security-policy": "Content Security Policy",
        "referrer-policy": "Referrer Policy",
        "permissions-policy": "Permissions Policy",
        "feature-policy": "Feature Policy (deprecated)",
        "cache-control": "Cache Control",
        "x-permitted-cross-domain-policies": "Cross Domain Policy",
        "cross-origin-opener-policy": "Cross-Origin Opener Policy",
        "cross-origin-resource-policy": "Cross-Origin Resource Policy",
        "cross-origin-embedder-policy": "Cross-Origin Embedder Policy",
    }

    # Strip ANSI codes from shcheck output
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    clean_output = ansi_escape.sub('', output)

    present_headers = {}
    missing_headers = set()

    for line in clean_output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Pattern: "Header present: X-Frame-Options: DENY"
        present_match = re.match(r".*?(\S[\w-]+)\s*[:]\s*(.+)", line)

        # Pattern: "[!] Missing header: X-Content-Type-Options"
        missing_match = re.match(r".*?[Mm]issing.*?:\s*(.+)", line)

        # Pattern: "X-Frame-Options ........... [ Present ]"
        dotted_present = re.match(r"([\w-]+)\s*\.+\s*\[\s*Present\s*\]", line, re.IGNORECASE)
        dotted_missing = re.match(r"([\w-]+)\s*\.+\s*\[\s*(?:Missing|Not Present)\s*\]", line, re.IGNORECASE)

        # Pattern: "[*] X-Frame-Options: DENY"
        star_match = re.match(r"\[\*\]\s*([\w-]+)\s*:\s*(.+)", line)

        # Pattern: "[!] X-Frame-Options: Missing"
        bang_match = re.match(r"\[!\]\s*([\w-]+).*?(?:missing|not present|not found)", line, re.IGNORECASE)
        bang_match2 = re.match(r"\[!\]\s*(?:Missing|Header not found).*?([\w-]+)", line, re.IGNORECASE)

        if star_match:
            header = star_match.group(1).lower()
            value = star_match.group(2).strip()
            present_headers[header] = value
        elif bang_match:
            header = bang_match.group(1).lower()
            missing_headers.add(header)
        elif bang_match2:
            header = bang_match2.group(1).lower()
            missing_headers.add(header)
        elif dotted_present:
            header = dotted_present.group(1).lower()
            present_headers[header] = "Present (value not shown)"
        elif dotted_missing:
            header = dotted_missing.group(1).lower()
            missing_headers.add(header)
        elif missing_match:
            header_name = missing_match.group(1).strip().lower()
            # Could be a full name like "X-Content-Type-Options"
            if re.match(r'^[\w-]+$', header_name):
                missing_headers.add(header_name)

    # Build findings from parsed shcheck output
    for header, info in EXPECTED_HEADERS.items():
        if header in present_headers:
            findings.append({
                "check": "Security Header",
                "item": info["description"],
                "status": "Present",
                "value": present_headers[header],
                "recommendation": "",
            })
        elif header in missing_headers:
            findings.append({
                "check": "Security Header",
                "item": info["description"],
                "status": "Missing",
                "value": "",
                "recommendation": info["recommended"],
            })

    # If shcheck didn't cover all our expected headers, supplement with our own check
    if not findings:
        return None

    # Check for information disclosure headers in shcheck output
    for header in INFORMATION_DISCLOSURE_HEADERS:
        if header in present_headers:
            findings.append({
                "check": "Information Disclosure",
                "item": f"Header: {header}",
                "status": "Exposed",
                "value": present_headers[header],
                "recommendation": "Remove or suppress version information",
            })

    # CSP analysis if present
    csp_value = present_headers.get("content-security-policy", "")
    if csp_value and csp_value != "Present (value not shown)":
        findings.extend(analyse_csp(csp_value))

    return findings


# --- CSP Analysis ---

CSP_DANGEROUS_DIRECTIVES = {
    "unsafe-inline": "Allows inline script/style execution, defeats purpose of CSP",
    "unsafe-eval": "Allows eval() and similar dynamic code execution",
    "unsafe-hashes": "Allows specific inline event handlers by hash",
    "data:": "Allows data: URIs which can be used to inject content",
    "blob:": "Allows blob: URIs which can execute arbitrary code",
    "*": "Wildcard allows loading resources from any origin",
}

CSP_EXPECTED_DIRECTIVES = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "object-src",
    "frame-ancestors",
    "base-uri",
    "form-action",
]


def analyse_csp(csp_value):
    """Analyse Content Security Policy for weaknesses."""
    findings = []

    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directive_name = tokens[0].lower()
            directive_values = tokens[1:] if len(tokens) > 1 else []
            directives[directive_name] = directive_values

    # Check for dangerous values in each directive
    for directive, values in directives.items():
        for value in values:
            value_lower = value.strip("'").lower()
            for dangerous, reason in CSP_DANGEROUS_DIRECTIVES.items():
                if dangerous in value_lower:
                    findings.append({
                        "check": "CSP Analysis",
                        "item": f"{directive}: {value}",
                        "status": "Weak",
                        "value": reason,
                        "recommendation": f"Remove '{dangerous}' from {directive}",
                    })

    # Check for overly permissive sources
    for directive, values in directives.items():
        for value in values:
            if value == "https:" and directive in ("script-src", "default-src"):
                findings.append({
                    "check": "CSP Analysis",
                    "item": f"{directive}: https:",
                    "status": "Weak",
                    "value": "Allows scripts from any HTTPS origin",
                    "recommendation": "Restrict to specific trusted domains",
                })
            elif value == "http:" and directive in ("script-src", "default-src"):
                findings.append({
                    "check": "CSP Analysis",
                    "item": f"{directive}: http:",
                    "status": "Weak",
                    "value": "Allows scripts from any HTTP origin (no TLS)",
                    "recommendation": "Restrict to specific trusted HTTPS domains",
                })

    # Check for missing directives
    for expected in CSP_EXPECTED_DIRECTIVES:
        if expected not in directives:
            has_default = "default-src" in directives
            if expected == "default-src" or not has_default:
                findings.append({
                    "check": "CSP Analysis",
                    "item": f"Missing: {expected}",
                    "status": "Missing",
                    "value": "Directive not defined and no default-src fallback" if not has_default else "Directive not explicitly defined",
                    "recommendation": f"Add {expected} directive",
                })

    # Check if script-src or default-src use nonce or hash (best practice)
    script_src = directives.get("script-src", directives.get("default-src", []))
    has_nonce = any("nonce-" in v for v in script_src)
    has_hash = any("sha256-" in v or "sha384-" in v or "sha512-" in v for v in script_src)
    has_strict_dynamic = any("strict-dynamic" in v for v in script_src)

    if has_nonce or has_hash:
        findings.append({
            "check": "CSP Analysis",
            "item": "Nonce/Hash based CSP",
            "status": "Present",
            "value": "Uses nonce" if has_nonce else "Uses hash-based allowlisting",
            "recommendation": "",
        })
    if has_strict_dynamic:
        findings.append({
            "check": "CSP Analysis",
            "item": "strict-dynamic",
            "status": "Present",
            "value": "Propagates trust to dynamically loaded scripts",
            "recommendation": "",
        })

    # Check for report-uri / report-to
    has_reporting = "report-uri" in directives or "report-to" in directives
    if not has_reporting:
        findings.append({
            "check": "CSP Analysis",
            "item": "CSP Reporting",
            "status": "Missing",
            "value": "No report-uri or report-to configured",
            "recommendation": "Add reporting to monitor CSP violations",
        })

    # Summary
    if not findings:
        findings.append({
            "check": "CSP Analysis",
            "item": "Policy",
            "status": "Strong",
            "value": "No obvious weaknesses detected in CSP",
            "recommendation": "",
        })

    return findings


# --- SSL/TLS Checks ---

TLS_VERSIONS = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None, "Deprecated"),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None, "Deprecated"),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2, "Acceptable"),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None, "Recommended"),
]

WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5", "RC2",
]


def check_ssl_certificate(hostname, port=443):
    """Check SSL certificate validity."""
    findings = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)

                days_remaining = (not_after - now).days

                if days_remaining < 0:
                    cert_status = "Expired"
                elif days_remaining < 30:
                    cert_status = "Expiring Soon"
                else:
                    cert_status = "Valid"

                findings.append({
                    "check": "SSL Certificate",
                    "item": "Validity",
                    "status": cert_status,
                    "value": f"Expires: {not_after.strftime('%Y-%m-%d')} ({days_remaining} days remaining)",
                    "recommendation": "Renew certificate" if cert_status != "Valid" else "",
                })

                subject = dict(x[0] for x in cert["subject"])
                issuer = dict(x[0] for x in cert["issuer"])

                findings.append({
                    "check": "SSL Certificate",
                    "item": "Subject",
                    "status": "Info",
                    "value": subject.get("commonName", "N/A"),
                    "recommendation": "",
                })

                findings.append({
                    "check": "SSL Certificate",
                    "item": "Issuer",
                    "status": "Info",
                    "value": issuer.get("organizationName", issuer.get("commonName", "N/A")),
                    "recommendation": "",
                })

                san = []
                for type_, value in cert.get("subjectAltName", []):
                    if type_ == "DNS":
                        san.append(value)
                findings.append({
                    "check": "SSL Certificate",
                    "item": "Subject Alt Names",
                    "status": "Info",
                    "value": ", ".join(san[:5]) + (f" (+{len(san)-5} more)" if len(san) > 5 else ""),
                    "recommendation": "",
                })

                findings.append({
                    "check": "SSL Certificate",
                    "item": "Serial Number",
                    "status": "Info",
                    "value": cert.get("serialNumber", "N/A"),
                    "recommendation": "",
                })

                version = ssock.version()
                findings.append({
                    "check": "SSL Certificate",
                    "item": "Negotiated Protocol",
                    "status": "Info",
                    "value": version,
                    "recommendation": "",
                })

    except ssl.SSLCertVerificationError as e:
        findings.append({
            "check": "SSL Certificate",
            "item": "Validation",
            "status": "Invalid",
            "value": str(e).split(":")[0] if ":" in str(e) else str(e),
            "recommendation": "Fix certificate trust chain",
        })
    except Exception as e:
        findings.append({
            "check": "SSL Certificate",
            "item": "Connection",
            "status": "Error",
            "value": str(e),
            "recommendation": "",
        })

    return findings


def check_tls_versions(hostname, port=443):
    """Check which TLS versions are supported."""
    findings = []

    for name, version_const, rating in TLS_VERSIONS:
        if version_const is None:
            continue

        supported = False
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version_const
            context.maximum_version = version_const

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    supported = True
        except (ssl.SSLError, OSError, ConnectionRefusedError):
            supported = False

        status = "Supported" if supported else "Not Supported"
        recommendation = ""
        if supported and rating == "Deprecated":
            recommendation = f"Disable {name} - deprecated and insecure"

        findings.append({
            "check": "TLS Version",
            "item": name,
            "status": status,
            "value": rating if supported else "N/A",
            "recommendation": recommendation,
        })

    return findings


def check_cipher_suites(hostname, port=443):
    """Check for weak cipher suites."""
    findings = []

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    cipher_name, tls_ver, bits = cipher
                    is_weak = any(w.lower() in cipher_name.lower() for w in WEAK_CIPHERS)

                    findings.append({
                        "check": "Cipher Suite",
                        "item": "Negotiated Cipher",
                        "status": "Weak" if is_weak else "Strong",
                        "value": f"{cipher_name} ({bits} bits, {tls_ver})",
                        "recommendation": "Disable weak cipher" if is_weak else "",
                    })

        # Test with only weak ciphers to see if server accepts them
        weak_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak_context.check_hostname = False
        weak_context.verify_mode = ssl.CERT_NONE
        weak_cipher_string = ":".join(["RC4", "DES", "3DES-EDE-CBC", "NULL", "EXPORT", "RC4-SHA", "DES-CBC3-SHA", "RC4-MD5"])
        try:
            weak_context.set_ciphers(weak_cipher_string)
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with weak_context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    weak_cipher = ssock.cipher()
                    findings.append({
                        "check": "Cipher Suite",
                        "item": "Weak Cipher Accepted",
                        "status": "Vulnerable",
                        "value": f"{weak_cipher[0]} ({weak_cipher[2]} bits)",
                        "recommendation": "Disable weak cipher suites",
                    })
        except (ssl.SSLError, OSError):
            findings.append({
                "check": "Cipher Suite",
                "item": "Weak Ciphers",
                "status": "Not Accepted",
                "value": "Server rejects weak cipher suites",
                "recommendation": "",
            })

    except Exception as e:
        findings.append({
            "check": "Cipher Suite",
            "item": "Check",
            "status": "Error",
            "value": str(e),
            "recommendation": "",
        })

    return findings


# --- WAF Detection ---

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
        "server": ["awselb", "amazons3"],
        "cookies": ["aws-waf-token", "awsalb"],
    },
    "Azure Front Door / Application Gateway": {
        "headers": ["x-azure-ref", "x-fd-healthprobe", "x-ms-routing-name"],
        "server": ["microsoft-azure", "microsoft-iis"],
        "cookies": ["ariafrontdoor", "applicationgatewayaffinity"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-session-info"],
        "server": ["akamaighost", "akamaighostnetworkstorage"],
        "cookies": ["akamai"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
        "cookies": ["incap_ses", "visid_incap", "__ut"],
    },
    "F5 BIG-IP": {
        "headers": ["x-wa-info", "x-cnection"],
        "server": ["big-ip", "bigip"],
        "cookies": ["bigipserver", "f5_cspm", "ts"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
        "cookies": ["sucuri_cloudproxy"],
    },
    "Barracuda": {
        "headers": ["barra_counter_session"],
        "server": ["barracuda"],
        "cookies": ["barra_counter_session", "bnh"],
    },
    "ModSecurity": {
        "headers": ["x-modsecurity-id", "x-modsecurity-error"],
        "server": ["mod_security", "modsecurity"],
        "cookies": [],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-restarts"],
        "server": ["fastly"],
        "cookies": [],
    },
}


def check_waf(url, timeout=15, wafw00f_file=None):
    """Detect Web Application Firewall using wafw00f."""
    findings = []
    import subprocess
    import glob
    import os

    # Try to find an existing wafw00f output file in the parent directory
    if not wafw00f_file:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        wafw00f_files = glob.glob(os.path.join(parent_dir, "wafw00f*"))
        if wafw00f_files:
            wafw00f_file = wafw00f_files[0]

    if wafw00f_file and os.path.isfile(wafw00f_file):
        try:
            with open(wafw00f_file, "r") as f:
                content = f.read()

            # Parse wafw00f output formats
            waf_name = ""
            # Format 1: "is behind <WAF Name>"
            waf_match = re.search(r"is behind\s+(.+?)(?:\n|$)", content)
            if waf_match:
                waf_name = waf_match.group(1).strip()
            else:
                # Format 2: tab/space separated — look for last known WAF name
                # e.g. "url  url (AWS Elastic Load Balancer)   AWS Elastic Load Balancer"
                # Take text after last parenthesised section
                trailing_match = re.search(r"\)\s+(.+?)$", content.strip(), re.MULTILINE)
                if trailing_match:
                    waf_name = trailing_match.group(1).strip()
                else:
                    # Try parenthesised name
                    paren_match = re.search(r"\(([^)]+)\)", content)
                    if paren_match:
                        waf_name = paren_match.group(1).strip()
                waf_match = bool(waf_name)

            if waf_match:
                if isinstance(waf_match, re.Match):
                    waf_name = waf_match.group(1).strip()
                findings.append({
                    "check": "WAF Detection",
                    "item": waf_name,
                    "status": "Detected",
                    "value": f"wafw00f output file: {os.path.basename(wafw00f_file)}",
                    "recommendation": "",
                })
                return findings
        except Exception:
            pass

    # Try running wafw00f live
    try:
        result = subprocess.run(
            ["wafw00f", url],
            capture_output=True, text=True, timeout=30,
        )
        output = result.stdout + result.stderr

        waf_match = re.search(r"is behind\s+(.+?)(?:\n|$)", output)
        if waf_match:
            waf_name = waf_match.group(1).strip()
            findings.append({
                "check": "WAF Detection",
                "item": waf_name,
                "status": "Detected",
                "value": f"wafw00f: {waf_name}",
                "recommendation": "",
            })
        elif "No WAF" in output or "is not behind" in output:
            findings.append({
                "check": "WAF Detection",
                "item": "Web Application Firewall",
                "status": "Not Detected",
                "value": "wafw00f: No WAF detected",
                "recommendation": "Consider implementing a WAF",
            })
        else:
            findings.extend(_check_waf_headers(url, timeout))

    except FileNotFoundError:
        print(f"  {C.YELLOW}[!] wafw00f not installed, falling back to header-based detection{C.RESET}")
        findings.extend(_check_waf_headers(url, timeout))
    except subprocess.TimeoutExpired:
        print(f"  {C.YELLOW}[!] wafw00f timed out, falling back to header-based detection{C.RESET}")
        findings.extend(_check_waf_headers(url, timeout))
    except Exception:
        findings.extend(_check_waf_headers(url, timeout))

    return findings


def _check_waf_headers(url, timeout=15):
    """Fallback WAF detection via headers and trigger requests."""
    findings = []
    detected_wafs = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        findings.append({
            "check": "WAF Detection",
            "item": "Connection",
            "status": "Error",
            "value": str(e),
            "recommendation": "",
        })
        return findings

    resp_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    server_header = resp_headers.get("server", "")
    cookies_str = " ".join([f"{k}={v}" for k, v in resp.cookies.items()]).lower()
    all_header_names = set(resp_headers.keys())

    for waf_name, signatures in WAF_SIGNATURES.items():
        evidence = []

        for h in signatures["headers"]:
            if h.lower() in all_header_names:
                evidence.append(f"header:{h}")

        for s in signatures["server"]:
            if s.lower() in server_header:
                evidence.append(f"server:{s}")

        for c in signatures["cookies"]:
            if c.lower() in cookies_str:
                evidence.append(f"cookie:{c}")

        if evidence:
            detected_wafs.append((waf_name, evidence))

    try:
        malicious_url = url.rstrip("/") + "/<script>alert(1)</script>"
        mal_resp = requests.get(malicious_url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        if mal_resp.status_code in (403, 406, 429, 501):
            block_evidence = f"HTTP {mal_resp.status_code} on malicious request"
            for waf_name, sigs in WAF_SIGNATURES.items():
                mal_headers = {k.lower(): v.lower() for k, v in mal_resp.headers.items()}
                for h in sigs["headers"]:
                    if h.lower() in mal_headers:
                        detected_wafs.append((waf_name, [block_evidence, f"header:{h}"]))
                        break
            if not detected_wafs:
                detected_wafs.append(("Unknown WAF", [block_evidence]))
    except Exception:
        pass

    if detected_wafs:
        seen = set()
        for waf_name, evidence in detected_wafs:
            if waf_name not in seen:
                seen.add(waf_name)
                findings.append({
                    "check": "WAF Detection",
                    "item": waf_name,
                    "status": "Detected",
                    "value": ", ".join(evidence),
                    "recommendation": "",
                })
    else:
        findings.append({
            "check": "WAF Detection",
            "item": "Web Application Firewall",
            "status": "Not Detected",
            "value": "No WAF signatures identified",
            "recommendation": "Consider implementing a WAF",
        })

    return findings


# --- Technology Fingerprinting ---

VERSION_PATTERN = re.compile(r"[\/@\-_v]?(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)")

NPM_PACKAGE_MAP = {
    "jQuery": "jquery",
    "Angular": "@angular/core",
    "AngularJS": "angular",
    "React": "react",
    "Vue.js": "vue",
    "Bootstrap": "bootstrap",
    "Tailwind CSS": "tailwindcss",
    "Lodash": "lodash",
    "Moment.js": "moment",
    "Axios": "axios",
    "Webpack": "webpack",
    "Vite": "vite",
    "Next.js": "next",
    "Nuxt.js": "nuxt",
    "Gatsby": "gatsby",
    "Ember.js": "ember-source",
    "Backbone.js": "backbone",
    "Knockout.js": "knockout",
    "Svelte": "svelte",
    "Alpine.js": "alpinejs",
    "htmx": "htmx.org",
    "GSAP": "gsap",
    "Three.js": "three",
    "D3.js": "d3",
    "Chart.js": "chart.js",
    "Font Awesome": "@fortawesome/fontawesome-free",
    "Sentry": "@sentry/browser",
    "Bulma": "bulma",
    "Foundation": "foundation-sites",
}

ENDOFLIFE_MAP = {
    "nginx": "nginx",
    "apache": "apache",
    "PHP": "php",
    "Django": "django",
    "Laravel": "laravel",
    "Ruby on Rails": "rails",
    "Node.js/Express": "nodejs",
    "WordPress": "wordpress",
    "Drupal": "drupal",
    "Java": "java",
    "ASP.NET": "dotnet",
}

SCRIPT_SIGNATURES = {
    "jquery": ("JavaScript Library", "jQuery"),
    "angular": ("JavaScript Framework", "Angular"),
    "react": ("JavaScript Framework", "React"),
    "vue": ("JavaScript Framework", "Vue.js"),
    "bootstrap": ("CSS Framework", "Bootstrap"),
    "tailwind": ("CSS Framework", "Tailwind CSS"),
    "lodash": ("JavaScript Library", "Lodash"),
    "moment": ("JavaScript Library", "Moment.js"),
    "axios": ("JavaScript Library", "Axios"),
    "webpack": ("Build Tool", "Webpack"),
    "vite": ("Build Tool", "Vite"),
    "next": ("JavaScript Framework", "Next.js"),
    "nuxt": ("JavaScript Framework", "Nuxt.js"),
    "gatsby": ("JavaScript Framework", "Gatsby"),
    "ember": ("JavaScript Framework", "Ember.js"),
    "backbone": ("JavaScript Framework", "Backbone.js"),
    "knockout": ("JavaScript Framework", "Knockout.js"),
    "svelte": ("JavaScript Framework", "Svelte"),
    "alpine": ("JavaScript Framework", "Alpine.js"),
    "htmx": ("JavaScript Library", "htmx"),
    "gsap": ("JavaScript Library", "GSAP"),
    "three": ("JavaScript Library", "Three.js"),
    "d3": ("JavaScript Library", "D3.js"),
    "chart": ("JavaScript Library", "Chart.js"),
    "recaptcha": ("Security", "Google reCAPTCHA"),
    "google-analytics": ("Analytics", "Google Analytics"),
    "gtag": ("Analytics", "Google Tag Manager"),
    "hotjar": ("Analytics", "Hotjar"),
    "sentry": ("Monitoring", "Sentry"),
    "cloudflare": ("CDN/Security", "Cloudflare"),
}

CSS_SIGNATURES = {
    "bootstrap": ("CSS Framework", "Bootstrap"),
    "tailwind": ("CSS Framework", "Tailwind CSS"),
    "font-awesome": ("Icon Library", "Font Awesome"),
    "material": ("CSS Framework", "Material Design"),
    "bulma": ("CSS Framework", "Bulma"),
    "foundation": ("CSS Framework", "Foundation"),
}

TECH_HEADER_MAP = {
    "server": ("Web Server", None),
    "x-powered-by": ("Framework", None),
    "x-aspnet-version": ("Framework", "ASP.NET"),
    "x-aspnetmvc-version": ("Framework", "ASP.NET MVC"),
    "x-generator": ("Generator", None),
    "x-drupal-cache": ("CMS", "Drupal"),
    "x-varnish": ("Cache", "Varnish"),
    "x-cache": ("CDN/Cache", None),
    "via": ("Proxy/CDN", None),
    "x-cdn": ("CDN", None),
}

COOKIE_SIGNATURES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "_rails": "Ruby on Rails",
    "connect.sid": "Node.js/Express",
}


def _extract_version(text, keyword):
    patterns = [
        re.compile(rf"{re.escape(keyword)}[\/@\-_v]*(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)", re.IGNORECASE),
        re.compile(rf"{re.escape(keyword)}.*?v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE),
        re.compile(rf"v?(\d+\.\d+(?:\.\d+)?).*?{re.escape(keyword)}", re.IGNORECASE),
    ]
    for pattern in patterns:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def _extract_version_from_header(value):
    match = re.search(r"[\/ ]v?(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)", value)
    return match.group(1) if match else None


def _get_current_version(technology):
    tech_name = technology.strip()
    npm_pkg = NPM_PACKAGE_MAP.get(tech_name)
    if npm_pkg:
        try:
            resp = requests.get(f"https://registry.npmjs.org/{npm_pkg}/latest", timeout=5)
            if resp.status_code == 200:
                return resp.json().get("version", "")
        except Exception:
            pass

    for key, product in ENDOFLIFE_MAP.items():
        if key.lower() in tech_name.lower():
            try:
                resp = requests.get(f"https://endoflife.date/api/{product}.json", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    if data and isinstance(data, list):
                        return data[0].get("latest", "") or data[0].get("latestVersion", "")
            except Exception:
                pass

    header_tech = tech_name.split("/")[0].strip().lower() if "/" in tech_name else ""
    if header_tech:
        for key, product in ENDOFLIFE_MAP.items():
            if key.lower() == header_tech or header_tech in key.lower():
                try:
                    resp = requests.get(f"https://endoflife.date/api/{product}.json", timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data and isinstance(data, list):
                            return data[0].get("latest", "") or data[0].get("latestVersion", "")
                except Exception:
                    pass
    return ""


def _detect_jquery_version(inline_raw, script_srcs):
    version, evidence = "", ""
    patterns = [
        re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)"),
        re.compile(r"jquery[.-](\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"jQuery JavaScript Library v(\d+\.\d+\.\d+)"),
    ]
    for p in patterns:
        match = p.search(inline_raw)
        if match:
            return match.group(1), match.group(0)[:100]
    for src in script_srcs:
        m = re.search(r"jquery[.-](\d+\.\d+\.\d+)", src, re.IGNORECASE)
        if m:
            return m.group(1), src
    return version, evidence


def _detect_react_version(inline_raw, script_srcs, base_url="", timeout=10, verify_ssl=True):
    version, evidence = "", ""
    patterns = [
        re.compile(r"React\s+v?(\d+\.\d+\.\d+)"),
        re.compile(r"react\.production\.min\.js.*?(\d+\.\d+\.\d+)"),
        re.compile(r'"react":\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r"react[./-](\d+\.\d+\.\d+)", re.IGNORECASE),
    ]
    for p in patterns:
        match = p.search(inline_raw)
        if match:
            return match.group(1), match.group(0)[:100]
    for src in script_srcs:
        m = re.search(r"react[./-]v?(\d+\.\d+\.\d+)", src, re.IGNORECASE)
        if m:
            return m.group(1), src
    if base_url:
        framework_scripts = [s for s in script_srcs if "framework" in s.lower() or "react" in s.lower()]
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        chunk_patterns = [
            re.compile(r"\.version\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']"),
            re.compile(r"react\.production\.min\.js.*?(\d+\.\d+\.\d+)"),
            re.compile(r"ReactVersion\s*=\s*[\"'](\d+\.\d+\.\d+)"),
            re.compile(r"react@(\d+\.\d+\.\d+)"),
        ]
        for script_path in framework_scripts[:2]:
            chunk_url = _resolve_script_url(script_path, base_url)
            if not chunk_url:
                continue
            try:
                resp = requests.get(chunk_url, headers=headers, timeout=timeout, verify=verify_ssl)
                if resp.status_code == 200:
                    for p in chunk_patterns:
                        match = p.search(resp.text)
                        if match:
                            return match.group(1), script_path
            except Exception:
                continue
    return version, evidence


def _detect_nextjs_version(soup, body_text, script_srcs, inline_raw, base_url="", timeout=10, verify_ssl=True):
    version, evidence = "", ""
    next_data = soup.find("script", id="__NEXT_DATA__")
    if next_data and next_data.string:
        try:
            data = json.loads(next_data.string)
            version = data.get("nextExport", {}).get("version", "") or data.get("version", "")
            if not version:
                runtime_config = data.get("runtimeConfig", {}) or data.get("props", {}).get("pageProps", {})
                version = runtime_config.get("nextVersion", "")
        except (json.JSONDecodeError, AttributeError):
            pass
        if version:
            evidence = "__NEXT_DATA__ script block"

    if not version:
        patterns = [
            re.compile(r"next[\\/](\d+\.\d+\.\d+)", re.IGNORECASE),
            re.compile(r"Next\.js\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE),
            re.compile(r'"next":\s*"[~^]?(\d+\.\d+\.\d+)"'),
        ]
        for p in patterns:
            match = p.search(inline_raw) or p.search(body_text)
            if match:
                version, evidence = match.group(1), match.group(0)[:100]
                break

    if not version and base_url:
        next_scripts = [s for s in script_srcs if "/_next/" in s.lower()]
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
        version_patterns = [
            re.compile(r"Next\.js\s+v?(\d+\.\d+\.\d+)"),
            re.compile(r'"next":\s*"[~^]?(\d+\.\d+\.\d+)"'),
            re.compile(r"next@(\d+\.\d+\.\d+)"),
        ]
        for script_path in sorted(next_scripts, key=lambda s: 0 if "webpack" in s.lower() else 1 if "main" in s.lower() else 2)[:5]:
            chunk_url = _resolve_script_url(script_path, base_url)
            if not chunk_url:
                continue
            try:
                resp = requests.get(chunk_url, headers=headers, timeout=timeout, verify=verify_ssl)
                if resp.status_code == 200:
                    for p in version_patterns:
                        match = p.search(resp.text)
                        if match:
                            return match.group(1), script_path
            except Exception:
                continue

    if not evidence:
        for src in script_srcs:
            if "/_next/" in src.lower():
                evidence = src
                break
        if not evidence:
            evidence = "/_next/static/ paths detected"
    return version, evidence


def _resolve_script_url(script_path, base_url):
    if script_path.startswith("http"):
        return script_path
    elif script_path.startswith("//"):
        return "https:" + script_path
    elif script_path.startswith("/"):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{script_path}"
    return None


def check_technology_stack(url, timeout=15, verify_ssl=False):
    """Fingerprint web technologies and look up current versions."""
    findings = []
    raw_techs = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl, allow_redirects=True)
    except requests.exceptions.SSLError:
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        findings.append({
            "check": "Technology Stack",
            "item": "Connection",
            "status": "Error",
            "value": str(e),
            "recommendation": "",
        })
        return findings

    resp_headers = {k.lower(): v for k, v in response.headers.items()}

    # Headers-based detection
    for header, (category, fixed_name) in TECH_HEADER_MAP.items():
        value = resp_headers.get(header)
        if value:
            version = _extract_version_from_header(value)
            tech_name = fixed_name if fixed_name else (value.split("/")[0].strip() if "/" in value else value)
            raw_techs.append({
                "technology": tech_name,
                "version": version or "",
                "evidence": f"{header}: {value}",
                "category": category,
            })

    # Cookie-based detection
    cookies = resp_headers.get("set-cookie", "")
    for sig, tech in COOKIE_SIGNATURES.items():
        if sig.lower() in cookies.lower():
            raw_techs.append({
                "technology": tech,
                "version": "",
                "evidence": f"Set-Cookie: {sig}",
                "category": "Framework/Language",
            })

    # HTML parsing
    soup = BeautifulSoup(response.text, "html.parser")

    # Meta generator
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        content = generator["content"]
        raw_techs.append({
            "technology": content,
            "version": _extract_version_from_header(content) or "",
            "evidence": f'<meta name="generator" content="{content}">',
            "category": "CMS/Generator",
        })

    # Script-based detection
    scripts = soup.find_all("script", src=True)
    script_srcs_raw = [s.get("src", "") for s in scripts]
    script_srcs_lower = " ".join([s.lower() for s in script_srcs_raw])
    inline_scripts_raw = []
    for s in soup.find_all("script"):
        if not s.string:
            continue
        if s.get("id") in ("__NEXT_DATA__", "__NUXT_DATA__"):
            continue
        if s.get("type") in ("application/json", "application/ld+json"):
            continue
        inline_scripts_raw.append(s.string)
    inline_lower = " ".join([s.lower() for s in inline_scripts_raw])
    all_content = script_srcs_lower + " " + inline_lower
    all_content_raw = " ".join(script_srcs_raw) + " " + " ".join(inline_scripts_raw)
    all_inline_raw = "\n".join(inline_scripts_raw)

    # False positive patterns: scripts that contain a keyword but aren't the technology
    _FALSE_POSITIVE_PATTERNS = {
        "bootstrap": re.compile(r"issueCollector|collectorBootstrap|ServiceWorker", re.IGNORECASE),
    }

    seen = set()
    for keyword, (category, tech) in SCRIPT_SIGNATURES.items():
        if keyword in all_content and tech not in seen:
            # Find the actual evidence source before committing
            evidence_src = ""
            for src in script_srcs_raw:
                if keyword in src.lower():
                    evidence_src = src
                    break

            # Check for false positives
            fp_pattern = _FALSE_POSITIVE_PATTERNS.get(keyword)
            if fp_pattern:
                if evidence_src and fp_pattern.search(evidence_src):
                    continue
                # Also check if the only inline match is a false positive
                inline_match = ""
                for script_text in inline_scripts_raw:
                    if keyword in script_text.lower():
                        inline_match = script_text
                        break
                if not evidence_src and inline_match and fp_pattern.search(inline_match):
                    continue

            seen.add(tech)
            version, evidence = "", ""

            if tech == "Next.js":
                version, evidence = _detect_nextjs_version(soup, response.text, script_srcs_raw, all_inline_raw, url, timeout, verify_ssl)
            elif tech == "React":
                version, evidence = _detect_react_version(all_inline_raw, script_srcs_raw, url, timeout, verify_ssl)
            elif tech == "jQuery":
                version, evidence = _detect_jquery_version(all_inline_raw, script_srcs_raw)
            else:
                version = _extract_version(all_content_raw, keyword)

            if not evidence:
                evidence = evidence_src
            if not evidence:
                for script_text in inline_scripts_raw:
                    if keyword in script_text.lower():
                        match_line = next((line.strip() for line in script_text.split("\n") if keyword in line.lower()), "")
                        evidence = match_line[:120] if match_line else ""
                        break

            raw_techs.append({
                "technology": tech,
                "version": version or "",
                "evidence": evidence,
                "category": category,
            })

    # CSS/link-based detection
    links = soup.find_all("link", href=True)
    link_hrefs_raw = [l.get("href", "") for l in links]
    link_hrefs_lower = " ".join([h.lower() for h in link_hrefs_raw])

    for keyword, (category, tech) in CSS_SIGNATURES.items():
        if keyword in link_hrefs_lower and tech not in seen:
            seen.add(tech)
            version = _extract_version(" ".join(link_hrefs_raw), keyword)
            evidence = ""
            for href in link_hrefs_raw:
                if keyword in href.lower():
                    evidence = href
                    break
            raw_techs.append({
                "technology": tech,
                "version": version or "",
                "evidence": evidence,
                "category": category,
            })

    # HTML structure detection
    if soup.find(attrs={"ng-app": True}) or soup.find(attrs={"ng-controller": True}):
        raw_techs.append({"technology": "AngularJS", "version": _extract_version(response.text, "angular") or "", "evidence": "ng-app/ng-controller attribute", "category": "JavaScript Framework"})
    if "wp-content" in response.text or "wp-includes" in response.text:
        raw_techs.append({"technology": "WordPress", "version": _extract_version(response.text, "wordpress") or "", "evidence": "/wp-content/ or /wp-includes/", "category": "CMS"})

    # Deduplicate
    seen_tech = {}
    for t in raw_techs:
        name = t["technology"]
        if name not in seen_tech or (t.get("version") and not seen_tech[name].get("version")):
            seen_tech[name] = t
    raw_techs = list(seen_tech.values())

    # Look up current versions and build findings
    for t in raw_techs:
        current = _get_current_version(t["technology"])
        installed = t["version"]
        installed_str = f"v{installed}" if installed else "Unknown"
        current_str = f"v{current}" if current else "N/A"

        if installed and current and installed == current:
            status = "Current"
            rec = ""
        elif installed and current and installed != current:
            status = "Outdated"
            rec = f"Update {t['technology']} from v{installed} to v{current}"
        elif not installed:
            status = "Detected"
            rec = "Version not identified -- verify manually"
        else:
            status = "Detected"
            rec = ""

        value = f"{installed_str} (current: {current_str})" if current else installed_str
        findings.append({
            "check": "Technology Stack",
            "item": f"{t['technology']}",
            "status": status,
            "value": value,
            "recommendation": rec,
        })

    if not findings:
        findings.append({
            "check": "Technology Stack",
            "item": "Detection",
            "status": "Info",
            "value": "No technologies identified from passive fingerprinting",
            "recommendation": "",
        })

    return findings


# --- Colours ---

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


STATUS_COLOURS = {
    "Present": C.GREEN,
    "Missing": C.RED,
    "Valid": C.GREEN,
    "Invalid": C.RED,
    "Expired": C.RED,
    "Expiring Soon": C.YELLOW,
    "Supported": C.GREEN,
    "Not Supported": C.GREY,
    "Strong": C.GREEN,
    "Weak": C.RED,
    "Not Accepted": C.GREEN,
    "Vulnerable": C.RED,
    "Detected": C.CYAN,
    "Not Detected": C.YELLOW,
    "Exposed": C.RED,
    "Info": C.BLUE,
    "Error": C.RED,
    "Deprecated": C.RED,
    "Acceptable": C.YELLOW,
    "Recommended": C.GREEN,
    "Current": C.GREEN,
    "Outdated": C.YELLOW,
}


def coloured_status(status):
    colour = STATUS_COLOURS.get(status, C.WHITE)
    return f"{colour}{status}{C.RESET}"


def coloured_value_for_tls(value):
    if value == "Deprecated":
        return f"{C.RED}{value}{C.RESET}"
    elif value == "Acceptable":
        return f"{C.YELLOW}{value}{C.RESET}"
    elif value == "Recommended":
        return f"{C.GREEN}{value}{C.RESET}"
    return value


# --- Output ---

def write_csv(findings, output_file):
    """Write findings to CSV."""
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Check", "Item", "Status", "Value", "Recommendation"])
        for finding in findings:
            writer.writerow([
                finding["check"],
                finding["item"],
                finding["status"],
                finding["value"],
                finding["recommendation"],
            ])


def write_markdown(findings, output_file, url=""):
    """Write findings to Markdown."""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# Pre-Authentication Reconnaissance\n\n")
        if url:
            f.write(f"**Target:** {url}\n\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("---\n\n")

        current_check = ""
        for finding in findings:
            if finding["check"] != current_check:
                current_check = finding["check"]
                f.write(f"## {current_check}\n\n")
                f.write("| Item | Status | Value | Recommendation |\n")
                f.write("|------|--------|-------|----------------|\n")

            rec = finding["recommendation"] if finding["recommendation"] else "-"
            value = finding["value"] if finding["value"] else "-"
            # Escape pipe chars in values for markdown tables
            value = value.replace("|", "\\|")
            rec = rec.replace("|", "\\|")

            f.write(f"| {finding['item']} | {finding['status']} | {value} | {rec} |\n")

        f.write("\n---\n")


def print_findings(findings):
    """Print findings in a table format."""
    current_check = ""
    for f in findings:
        if f["check"] != current_check:
            current_check = f["check"]
            print(f"\n  {C.BOLD}{C.CYAN}[{current_check}]{C.RESET}")
            print(f"    {'Item':<35} | {'Status':<15} | Value")
            print(f"    {C.DIM}{'-'*35}-+-{'-'*15}-+-{'-'*60}{C.RESET}")

        status_str = coloured_status(f["status"])
        # Pad accounting for ANSI escape codes (they don't take visual space)
        status_pad = 15 + len(status_str) - len(f["status"])

        value = f["value"]
        if f["check"] == "TLS Version" and f["status"] == "Supported":
            value = coloured_value_for_tls(value)
        elif f["check"] == "TLS Version" and f["status"] == "Not Supported" and f["item"] == "TLSv1.3":
            value = f"{C.YELLOW}Not available{C.RESET}"

        rec = ""
        if f["recommendation"]:
            rec = f" {C.YELLOW}>> {f['recommendation']}{C.RESET}"

        print(f"    {f['item']:<35} | {status_str:<{status_pad}} | {value}{rec}")


def main():
    parser = argparse.ArgumentParser(description="Pre-authentication reconnaissance - headers, SSL/TLS, WAF")
    parser.add_argument("url", nargs="?", help="Target URL")
    parser.add_argument("-f", "--file", help="File containing target URLs (one per line)")
    parser.add_argument("-o", "--output", default="pre_auth_recon_results", help="Output file (extension added based on format)")
    parser.add_argument("--format", choices=["csv", "md", "both"], default="csv", help="Output format: csv, md, or both (default: csv)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--skip-headers", action="store_true", help="Skip security headers check")
    parser.add_argument("--skip-ssl", action="store_true", help="Skip SSL/TLS checks")
    parser.add_argument("--skip-waf", action="store_true", help="Skip WAF detection")
    parser.add_argument("--skip-tech", action="store_true", help="Skip technology fingerprinting")
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error("Provide a URL or a file with -f")

    urls = []
    if args.file:
        with open(args.file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [args.url]

    all_findings = []

    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        print(f"\n{C.BOLD}{C.WHITE}[*] Target: {C.CYAN}{url}{C.RESET}")
        print(f"{C.DIM}{'='*70}{C.RESET}")

        if not args.skip_headers:
            print(f"\n{C.BOLD}[*]{C.RESET} Checking security headers...")
            header_findings = check_security_headers(url, timeout=args.timeout)
            all_findings.extend(header_findings)
            print_findings(header_findings)

        if not args.skip_ssl:
            print(f"\n{C.BOLD}[*]{C.RESET} Checking SSL certificate...")
            cert_findings = check_ssl_certificate(hostname, port)
            all_findings.extend(cert_findings)
            print_findings(cert_findings)

            print(f"\n{C.BOLD}[*]{C.RESET} Checking TLS versions...")
            tls_findings = check_tls_versions(hostname, port)
            all_findings.extend(tls_findings)
            print_findings(tls_findings)

            print(f"\n{C.BOLD}[*]{C.RESET} Checking cipher suites...")
            cipher_findings = check_cipher_suites(hostname, port)
            all_findings.extend(cipher_findings)
            print_findings(cipher_findings)

        if not args.skip_waf:
            print(f"\n{C.BOLD}[*]{C.RESET} Detecting WAF...")
            waf_findings = check_waf(url, timeout=args.timeout)
            all_findings.extend(waf_findings)
            print_findings(waf_findings)

        if not args.skip_tech:
            print(f"\n{C.BOLD}[*]{C.RESET} Fingerprinting technology stack...")
            tech_findings = check_technology_stack(url, timeout=args.timeout)
            all_findings.extend(tech_findings)
            print_findings(tech_findings)

    # Strip extension from output if user provided one
    output_base = args.output
    if output_base.endswith((".csv", ".md")):
        output_base = output_base.rsplit(".", 1)[0]

    target_url = urls[0] if len(urls) == 1 else "multiple targets"

    if args.format in ("csv", "both"):
        csv_file = f"{output_base}.csv"
        write_csv(all_findings, csv_file)
        print(f"\n{C.GREEN}{C.BOLD}[+]{C.RESET} CSV saved to: {C.WHITE}{csv_file}{C.RESET}")

    if args.format in ("md", "both"):
        md_file = f"{output_base}.md"
        write_markdown(all_findings, md_file, url=target_url)
        print(f"{C.GREEN}{C.BOLD}[+]{C.RESET} Markdown saved to: {C.WHITE}{md_file}{C.RESET}")


if __name__ == "__main__":
    main()
