#!/usr/bin/env python3
"""Technology fingerprinting script - identifies technologies used on a target URL."""

import argparse
import csv
import json
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

import urllib3
import requests
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls):
        for attr in ["RED", "GREEN", "YELLOW", "BLUE", "CYAN", "WHITE", "GREY", "BOLD", "DIM", "RESET"]:
            setattr(cls, attr, "")


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


def get_current_version(technology):
    """Look up the current/latest version of a technology."""
    tech_name = technology.strip()

    npm_pkg = NPM_PACKAGE_MAP.get(tech_name)
    if npm_pkg:
        try:
            resp = requests.get(
                f"https://registry.npmjs.org/{npm_pkg}/latest",
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("version", "")
        except Exception:
            pass

    for key, product in ENDOFLIFE_MAP.items():
        if key.lower() in tech_name.lower():
            try:
                resp = requests.get(
                    f"https://endoflife.date/api/{product}.json",
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data and isinstance(data, list):
                        latest = data[0].get("latest", "") or data[0].get("latestVersion", "")
                        if latest:
                            return latest
            except Exception:
                pass

    header_tech = tech_name.split("/")[0].strip().lower() if "/" in tech_name else ""
    if header_tech:
        for key, product in ENDOFLIFE_MAP.items():
            if key.lower() == header_tech or header_tech in key.lower():
                try:
                    resp = requests.get(
                        f"https://endoflife.date/api/{product}.json",
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if data and isinstance(data, list):
                            latest = data[0].get("latest", "") or data[0].get("latestVersion", "")
                            if latest:
                                return latest
                except Exception:
                    pass

    return ""


def extract_version(text, keyword):
    """Extract version number near a keyword reference."""
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


def extract_version_from_header(value):
    """Extract version from a header value like 'nginx/1.18.0' or 'PHP/8.1.2'."""
    match = re.search(r"[\/ ]v?(\d+\.\d+(?:\.\d+)?(?:[-_.]\w+)?)", value)
    if match:
        return match.group(1)
    return None


def get_headers_tech(headers):
    """Identify technologies from HTTP response headers."""
    findings = []

    header_map = {
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

    for header, (category, fixed_name) in header_map.items():
        value = headers.get(header)
        if value:
            version = extract_version_from_header(value)
            if fixed_name:
                tech_name = fixed_name
                tech_version = version or value
            else:
                tech_name = value.split("/")[0].strip() if "/" in value else value
                tech_version = version or ""
            findings.append({
                "category": category,
                "technology": tech_name,
                "version": tech_version,
                "evidence": f"{header}: {value}",
                "source": f"HTTP Header: {header}",
            })

    cookies = headers.get("set-cookie", "")
    cookie_signatures = {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "csrftoken": "Django",
        "laravel_session": "Laravel",
        "_rails": "Ruby on Rails",
        "connect.sid": "Node.js/Express",
    }
    for sig, tech in cookie_signatures.items():
        if sig.lower() in cookies.lower():
            findings.append({
                "category": "Framework/Language",
                "technology": tech,
                "version": "",
                "evidence": f"Set-Cookie: {sig}",
                "source": f"Cookie: {sig}",
            })

    return findings


def get_meta_tech(soup):
    """Identify technologies from HTML meta tags."""
    findings = []

    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        content = generator["content"]
        version = extract_version_from_header(content)
        findings.append({
            "category": "CMS/Generator",
            "technology": content,
            "version": version or "",
            "evidence": f'<meta name="generator" content="{content}">',
            "source": "Meta: generator",
        })


    return findings


def _detect_nextjs_version(soup, body_text, script_srcs, inline_raw, base_url="", timeout=10, verify_ssl=True):
    """Detect Next.js version from __NEXT_DATA__, chunk files, or known patterns."""
    version = ""
    evidence = ""

    next_data = soup.find("script", id="__NEXT_DATA__")
    if next_data and next_data.string:
        try:
            data = json.loads(next_data.string)
            version = data.get("nextExport", {}).get("version", "")
            if not version:
                version = data.get("version", "")
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
            re.compile(r"nextVersion[\"':\s]+(\d+\.\d+\.\d+)"),
            re.compile(r"__NEXT_VERSION__[\"':\s]+[\"'](\d+\.\d+\.\d+)"),
        ]
        for p in patterns:
            match = p.search(inline_raw) or p.search(body_text)
            if match:
                version = match.group(1)
                evidence = match.group(0)[:100]
                break

    if not version and base_url:
        next_scripts = [s for s in script_srcs if "/_next/" in s.lower()]
        priority_scripts = sorted(next_scripts, key=lambda s: (
            0 if "webpack" in s.lower() else
            1 if "main" in s.lower() else
            2 if "framework" in s.lower() else
            3 if "polyfill" not in s.lower() else 4
        ))

        version_patterns = [
            re.compile(r"Next\.js\s+v?(\d+\.\d+\.\d+)"),
            re.compile(r'"next":\s*"[~^]?(\d+\.\d+\.\d+)"'),
            re.compile(r"next@(\d+\.\d+\.\d+)"),
            re.compile(r"next[/\\](\d+\.\d+\.\d+)"),
            re.compile(r"__NEXT_VERSION__\s*=\s*[\"'](\d+\.\d+\.\d+)"),
            re.compile(r"nextVersion[\"':,\s]+[\"']?(\d+\.\d+\.\d+)"),
            re.compile(r"[\"']next[\"'][,:}\s]+[\"'](\d+\.\d+\.\d+)[\"']"),
        ]

        semver_pattern = re.compile(r'[=\"](\d+\.\d+\.\d+)["\',]')

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        for script_path in priority_scripts[:5]:
            if script_path.startswith("http"):
                chunk_url = script_path
            elif script_path.startswith("//"):
                chunk_url = "https:" + script_path
            elif script_path.startswith("/"):
                parsed = urlparse(base_url)
                chunk_url = f"{parsed.scheme}://{parsed.netloc}{script_path}"
            else:
                continue

            try:
                resp = requests.get(chunk_url, headers=headers, timeout=timeout, verify=verify_ssl)
                if resp.status_code == 200:
                    for p in version_patterns:
                        match = p.search(resp.text)
                        if match:
                            version = match.group(1)
                            evidence = script_path
                            return version, evidence

                    if "main" in script_path.lower():
                        semvers = semver_pattern.findall(resp.text)
                        non_react = [v for v in semvers if not v.startswith("18.")]
                        if non_react:
                            version = non_react[0]
                            evidence = script_path
                            return version, evidence
            except Exception:
                continue

    if not version:
        for src in script_srcs:
            m = re.search(r"next[/\\-]v?(\d+\.\d+\.\d+)", src, re.IGNORECASE)
            if m:
                version = m.group(1)
                evidence = src
                break

    if not evidence:
        for src in script_srcs:
            if "/_next/" in src.lower():
                evidence = src
                break
        if not evidence:
            evidence = "/_next/static/ paths detected"

    return version, evidence


def _detect_react_version(inline_raw, script_srcs, base_url="", timeout=10, verify_ssl=True):
    """Detect React version from common patterns or framework chunk."""
    version = ""
    evidence = ""

    patterns = [
        re.compile(r"React\s+v?(\d+\.\d+\.\d+)"),
        re.compile(r"react\.production\.min\.js.*?(\d+\.\d+\.\d+)"),
        re.compile(r'"react":\s*"[~^]?(\d+\.\d+\.\d+)"'),
        re.compile(r"react[./-](\d+\.\d+\.\d+)", re.IGNORECASE),
    ]
    for p in patterns:
        match = p.search(inline_raw)
        if match:
            version = match.group(1)
            evidence = match.group(0)[:100]
            break

    if not version:
        for src in script_srcs:
            m = re.search(r"react[./-]v?(\d+\.\d+\.\d+)", src, re.IGNORECASE)
            if m:
                version = m.group(1)
                evidence = src
                break

    if not version and base_url:
        framework_scripts = [s for s in script_srcs if "framework" in s.lower()]
        if not framework_scripts:
            framework_scripts = [s for s in script_srcs if "react" in s.lower()]

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        chunk_patterns = [
            re.compile(r"\.version\s*=\s*[\"'](\d+\.\d+\.\d+)[\"']"),
            re.compile(r"react\.production\.min\.js.*?(\d+\.\d+\.\d+)"),
            re.compile(r"ReactVersion\s*=\s*[\"'](\d+\.\d+\.\d+)"),
            re.compile(r"react@(\d+\.\d+\.\d+)"),
        ]

        for script_path in framework_scripts[:2]:
            if script_path.startswith("http"):
                chunk_url = script_path
            elif script_path.startswith("//"):
                chunk_url = "https:" + script_path
            elif script_path.startswith("/"):
                parsed = urlparse(base_url)
                chunk_url = f"{parsed.scheme}://{parsed.netloc}{script_path}"
            else:
                continue

            try:
                resp = requests.get(chunk_url, headers=headers, timeout=timeout, verify=verify_ssl)
                if resp.status_code == 200:
                    for p in chunk_patterns:
                        match = p.search(resp.text)
                        if match:
                            version = match.group(1)
                            evidence = script_path
                            return version, evidence
            except Exception:
                continue

    return version, evidence


def _detect_jquery_version(inline_raw, script_srcs):
    """Detect jQuery version from common patterns."""
    version = ""
    evidence = ""

    patterns = [
        re.compile(r"jQuery\s+v?(\d+\.\d+\.\d+)"),
        re.compile(r"jquery[.-](\d+\.\d+\.\d+)", re.IGNORECASE),
        re.compile(r"jQuery JavaScript Library v(\d+\.\d+\.\d+)"),
    ]
    for p in patterns:
        match = p.search(inline_raw)
        if match:
            version = match.group(1)
            evidence = match.group(0)[:100]
            break

    if not version:
        for src in script_srcs:
            m = re.search(r"jquery[.-](\d+\.\d+\.\d+)", src, re.IGNORECASE)
            if m:
                version = m.group(1)
                evidence = src
                break

    return version, evidence


def get_script_tech(soup, body_text, base_url="", timeout=10, verify_ssl=True):
    """Identify technologies from script tags and inline JS."""
    findings = []

    script_signatures = {
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

    scripts = soup.find_all("script", src=True)
    script_srcs_raw = [s.get("src", "") for s in scripts]
    script_srcs = " ".join([s.lower() for s in script_srcs_raw])
    # Exclude __NEXT_DATA__ and other JSON data blocks from inline script matching
    inline_scripts_raw = []
    for s in soup.find_all("script"):
        if not s.string:
            continue
        if s.get("id") in ("__NEXT_DATA__", "__NUXT_DATA__"):
            continue
        if s.get("type") in ("application/json", "application/ld+json"):
            continue
        inline_scripts_raw.append(s.string)
    inline_scripts = " ".join([s.lower() for s in inline_scripts_raw])
    all_script_content = script_srcs + " " + inline_scripts
    all_script_content_raw = " ".join(script_srcs_raw) + " " + " ".join(inline_scripts_raw)
    all_inline_raw = "\n".join(inline_scripts_raw)

    _false_positive_patterns = {
        "bootstrap": re.compile(r"issueCollector|collectorBootstrap|ServiceWorker", re.IGNORECASE),
    }

    seen = set()
    for keyword, (category, tech) in script_signatures.items():
        if keyword in all_script_content and tech not in seen:
            # Check for false positives before committing
            fp_pattern = _false_positive_patterns.get(keyword)
            if fp_pattern:
                evidence_src = next((src for src in script_srcs_raw if keyword in src.lower()), "")
                if evidence_src and fp_pattern.search(evidence_src):
                    continue

            seen.add(tech)
            version = ""
            evidence = ""

            has_specific_detector = False

            if tech == "Next.js":
                has_specific_detector = True
                version, evidence = _detect_nextjs_version(soup, body_text, script_srcs_raw, all_inline_raw, base_url, timeout, verify_ssl)
            elif tech == "React":
                has_specific_detector = True
                version, evidence = _detect_react_version(all_inline_raw, script_srcs_raw, base_url, timeout, verify_ssl)
            elif tech == "jQuery":
                has_specific_detector = True
                version, evidence = _detect_jquery_version(all_inline_raw, script_srcs_raw)
            elif tech == "Webpack":
                has_specific_detector = True
                for src in script_srcs_raw:
                    if "webpack" in src.lower():
                        evidence = src
                        break

            if not version and not has_specific_detector:
                version = extract_version(all_script_content_raw, keyword)
            if not evidence:
                for src in script_srcs_raw:
                    if keyword in src.lower():
                        evidence = src
                        break
            if not evidence:
                for script_text in inline_scripts_raw:
                    if keyword in script_text.lower():
                        match_line = next((line.strip() for line in script_text.split("\n") if keyword in line.lower()), "")
                        evidence = match_line[:120] if match_line else ""
                        break
            findings.append({
                "category": category,
                "technology": tech,
                "version": version or "",
                "evidence": evidence,
                "source": f"Script reference: {keyword}",
            })

    return findings


def get_link_tech(soup):
    """Identify technologies from link tags and stylesheets."""
    findings = []

    css_signatures = {
        "bootstrap": ("CSS Framework", "Bootstrap"),
        "tailwind": ("CSS Framework", "Tailwind CSS"),
        "font-awesome": ("Icon Library", "Font Awesome"),
        "material": ("CSS Framework", "Material Design"),
        "bulma": ("CSS Framework", "Bulma"),
        "foundation": ("CSS Framework", "Foundation"),
    }

    links = soup.find_all("link", href=True)
    link_hrefs_raw = [l.get("href", "") for l in links]
    link_hrefs = " ".join([h.lower() for h in link_hrefs_raw])
    link_hrefs_full = " ".join(link_hrefs_raw)

    seen = set()
    for keyword, (category, tech) in css_signatures.items():
        if keyword in link_hrefs and tech not in seen:
            seen.add(tech)
            version = extract_version(link_hrefs_full, keyword)
            evidence = ""
            for href in link_hrefs_raw:
                if keyword in href.lower():
                    evidence = href
                    break
            findings.append({
                "category": category,
                "technology": tech,
                "version": version or "",
                "evidence": evidence,
                "source": f"Stylesheet: {keyword}",
            })

    return findings


def get_html_tech(soup, response_text, base_url="", timeout=10, verify_ssl=True):
    """Identify technologies from HTML structure and attributes."""
    findings = []

    ng_elem = soup.find(attrs={"ng-app": True}) or soup.find(attrs={"ng-controller": True})
    if ng_elem:
        version = extract_version(response_text, "angular")
        findings.append({
            "category": "JavaScript Framework",
            "technology": "AngularJS",
            "version": version or "",
            "evidence": str(ng_elem).split(">")[0] + ">",
            "source": "HTML attribute: ng-app/ng-controller",
        })

    react_elem = soup.find(attrs={"data-reactroot": True}) or soup.find(id="__next")
    if react_elem:
        script_srcs_raw = [s.get("src", "") for s in soup.find_all("script", src=True)]
        version, evidence = _detect_react_version("", script_srcs_raw, base_url, timeout, verify_ssl)
        if not evidence:
            evidence = "id=\"__next\"" if soup.find(id="__next") else "data-reactroot"
        findings.append({
            "category": "JavaScript Framework",
            "technology": "React",
            "version": version or "",
            "evidence": evidence,
            "source": "HTML attribute: data-reactroot/__next",
        })

    vue_elem = soup.find(attrs={"data-v-": re.compile(".*")}) or soup.find(id="__nuxt")
    if vue_elem:
        version = extract_version(response_text, "vue")
        findings.append({
            "category": "JavaScript Framework",
            "technology": "Vue.js",
            "version": version or "",
            "evidence": "id=\"__nuxt\"" if soup.find(id="__nuxt") else "data-v-* attribute",
            "source": "HTML attribute: data-v-*/__nuxt",
        })

    if "wp-content" in response_text or "wp-includes" in response_text:
        version = extract_version(response_text, "wordpress") or extract_version(response_text, "wp-")
        wp_match = re.search(r'(\/wp-(?:content|includes)[^\s"\'<>]*)', response_text)
        findings.append({
            "category": "CMS",
            "technology": "WordPress",
            "version": version or "",
            "evidence": wp_match.group(1) if wp_match else "/wp-content/",
            "source": "HTML: wp-content/wp-includes paths",
        })

    if "drupal" in response_text.lower():
        version = extract_version(response_text, "drupal")
        drupal_match = re.search(r'(\/sites\/[^\s"\'<>]*drupal[^\s"\'<>]*)', response_text, re.IGNORECASE)
        findings.append({
            "category": "CMS",
            "technology": "Drupal",
            "version": version or "",
            "evidence": drupal_match.group(1) if drupal_match else "Drupal reference in HTML",
            "source": "HTML: Drupal references",
        })


    return findings


def fingerprint_url(url, timeout=15, verify_ssl=True):
    """Perform technology fingerprinting on a URL."""
    findings = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout, verify=verify_ssl, allow_redirects=True)
    except requests.exceptions.SSLError:
        print(f"[!] SSL error, retrying without verification...")
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to {url}: {e}")
        return []

    findings.extend(get_headers_tech(response.headers))

    soup = BeautifulSoup(response.text, "html.parser")

    findings.extend(get_meta_tech(soup))
    findings.extend(get_script_tech(soup, response.text, base_url=url, timeout=timeout, verify_ssl=verify_ssl))
    findings.extend(get_link_tech(soup))
    findings.extend(get_html_tech(soup, response.text, base_url=url, timeout=timeout, verify_ssl=verify_ssl))

    # Deduplicate by technology name, keeping the one with a version
    seen_tech = {}
    for f in findings:
        name = f["technology"]
        if name not in seen_tech or (f.get("version") and not seen_tech[name].get("version")):
            seen_tech[name] = f
    findings = list(seen_tech.values())

    return findings


def write_csv(findings, output_file):
    """Write findings to CSV."""
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Technology", "Installed Version", "Current Version", "Evidence"])
        for finding in findings:
            version = finding.get("version", "")
            ver_str = f"v{version}" if version else "Unknown"
            current = finding.get("current_version", "")
            cur_str = f"v{current}" if current else "N/A"
            evidence = finding.get("evidence", "")
            findings_evidence = f"[{evidence}]" if evidence else ""
            writer.writerow([
                finding["technology"],
                ver_str,
                cur_str,
                findings_evidence,
            ])


def url_to_filename(url):
    """Convert a URL to a safe filename. e.g. https://example.com -> example.com"""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    return hostname.replace(":", "_").replace("/", "_")


def main():
    parser = argparse.ArgumentParser(description="Technology fingerprinting - identify web technologies on a target URL")
    parser.add_argument("url", nargs="?", help="Target URL to fingerprint")
    parser.add_argument("-f", "--file", help="File containing target URLs (one per line)")
    parser.add_argument("-o", "--output-dir", default=".", help="Output directory for results (default: current directory)")
    parser.add_argument("-t", "--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--no-color", action="store_true", help="Disable coloured output")
    args = parser.parse_args()

    if args.no_color:
        C.disable()

    if not args.url and not args.file:
        parser.error("Provide a URL or a file with -f")

    urls = []
    if args.file:
        with open(args.file, "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    else:
        urls = [args.url]

    import os
    os.makedirs(args.output_dir, exist_ok=True)

    for url in urls:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        site_name = url_to_filename(url)
        output_file = os.path.join(args.output_dir, f"{site_name}_fingerprint.csv")

        print(f"{C.BOLD}[*]{C.RESET} Fingerprinting: {C.CYAN}{url}{C.RESET}")
        findings = fingerprint_url(url, timeout=args.timeout, verify_ssl=not args.insecure)

        print(f"{C.GREEN}{C.BOLD}[+]{C.RESET} Found {C.WHITE}{len(findings)}{C.RESET} technology indicators")
        print(f"{C.BOLD}[*]{C.RESET} Looking up current versions...\n")
        for f in findings:
            current = get_current_version(f["technology"])
            f["current_version"] = current

        print(f"    {C.BOLD}{'Technology':<25} | {'Installed Version':<20} | {'Current Version':<20} | Evidence{C.RESET}")
        print(f"    {C.DIM}{'-'*25}-+-{'-'*20}-+-{'-'*20}-+-{'-'*50}{C.RESET}")
        for f in findings:
            ver = f.get("version", "")
            ver_str = f"v{ver}" if ver else "Unknown"
            current = f.get("current_version", "")
            cur_str = f"v{current}" if current else "N/A"
            evidence = f.get("evidence", "")
            ev_str = f"[{evidence}]" if evidence else ""

            if ver and current:
                if ver == current:
                    ver_coloured = f"{C.GREEN}{ver_str}{C.RESET}"
                else:
                    ver_coloured = f"{C.YELLOW}{ver_str}{C.RESET}"
                cur_coloured = f"{C.GREEN}{cur_str}{C.RESET}"
            elif not ver:
                ver_coloured = f"{C.GREY}{ver_str}{C.RESET}"
                cur_coloured = f"{C.GREY}{cur_str}{C.RESET}"
            else:
                ver_coloured = ver_str
                cur_coloured = cur_str

            ver_pad = 20 + len(ver_coloured) - len(ver_str)
            cur_pad = 20 + len(cur_coloured) - len(cur_str)

            print(f"    {C.WHITE}{f['technology']:<25}{C.RESET} | {ver_coloured:<{ver_pad}} | {cur_coloured:<{cur_pad}} | {C.DIM}{ev_str}{C.RESET}")

        write_csv(findings, output_file)
        print(f"\n{C.GREEN}{C.BOLD}[+]{C.RESET} Results saved to: {C.WHITE}{output_file}{C.RESET}")
        print()


if __name__ == "__main__":
    main()
