#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import re
import shutil
import socket
import subprocess
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

PROVIDERS = {
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "amazonaws.com": "Amazon Web Services",
    "cloudfront.net": "AWS CloudFront",
    "elb.amazonaws.com": "AWS ELB",
    "vercel.app": "Vercel",
    "netlify.app": "Netlify",
    "pages.dev": "Cloudflare Pages",
    "workers.dev": "Cloudflare Workers",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "pantheonsite.io": "Pantheon",
    "wpengine.com": "WPEngine",
    "fastly.net": "Fastly",
    "shopify.com": "Shopify",
}


def log(msg):
    print(msg, flush=True)


def tool_exists(tool):
    return shutil.which(tool) is not None


def run_cmd(cmd, timeout=120):
    try:
        return subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return ""


def http_get(url):
    try:
        req = Request(url, headers={"User-Agent": "orphan-domain-finder/2.2"})
        with urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_domains(text, root_domain):
    found = set()
    root_domain = root_domain.lower().strip(".")

    for match in DOMAIN_RE.findall(text):
        domain = match.lower().strip(".").lstrip("*.")
        if domain == root_domain or domain.endswith("." + root_domain):
            found.add(domain)

    return found


def resolve_domain(domain):
    ips = set()
    try:
        for item in socket.getaddrinfo(domain, None):
            ips.add(item[4][0])
    except Exception:
        pass
    return sorted(ips)


def dig_record(domain, record_type):
    if not tool_exists("dig"):
        return []

    out = run_cmd(["dig", "+short", record_type, domain])
    return sorted({x.strip().strip('"') for x in out.splitlines() if x.strip()})


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0].rstrip(".").lower()
    except Exception:
        return ""


def detect_provider(cname, ips):
    joined_cname = " ".join(cname).lower()

    for indicator, provider in PROVIDERS.items():
        if indicator in joined_cname:
            return provider, indicator

    for ip in ips:
        data = http_get(f"https://ipinfo.io/{ip}/json")
        if not data:
            continue

        try:
            info = json.loads(data)
            org = info.get("org", "")
            if org:
                return org, ip
        except Exception:
            continue

    return "", ""


def query_crtsh(root_domain):
    log("[+] Querying crt.sh")
    url = f"https://crt.sh/?q=%25.{quote(root_domain)}&output=json"
    data = http_get(url)
    found = set()

    try:
        rows = json.loads(data)
        for row in rows:
            name = row.get("name_value", "")
            found.update(extract_domains(name.replace("\\n", "\n"), root_domain))
    except Exception:
        found.update(extract_domains(data, root_domain))

    return found


def query_wayback(root_domain):
    log("[+] Querying Wayback CDX")
    url = (
        "https://web.archive.org/cdx?url=*."
        + quote(root_domain)
        + "/*&output=json&fl=original&collapse=urlkey"
    )
    data = http_get(url)
    return extract_domains(data, root_domain)


def query_hackertarget(root_domain):
    log("[+] Querying HackerTarget hostsearch")
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(root_domain)}"
    data = http_get(url)
    return extract_domains(data, root_domain)


def query_rapiddns(root_domain):
    log("[+] Querying RapidDNS")
    url = f"https://rapiddns.io/subdomain/{quote(root_domain)}?full=1"
    data = http_get(url)
    return extract_domains(data, root_domain)


def run_subfinder(root_domain):
    if not tool_exists("subfinder"):
        log("[!] subfinder not found, skipping")
        return set()

    log("[+] Running subfinder")
    out = run_cmd(["subfinder", "-silent", "-all", "-d", root_domain], timeout=300)
    return extract_domains(out, root_domain)


def run_amass(root_domain):
    if not tool_exists("amass"):
        log("[!] amass not found, skipping")
        return set()

    log("[+] Running amass passive")
    out = run_cmd(["amass", "enum", "-passive", "-d", root_domain], timeout=600)
    return extract_domains(out, root_domain)


def run_dns_bruteforce(root_domain, wordlist):
    if not wordlist:
        return set()

    path = Path(wordlist)
    if not path.exists():
        log(f"[!] Wordlist not found: {wordlist}")
        return set()

    words = [x.strip() for x in path.read_text(errors="ignore").splitlines() if x.strip()]
    log(f"[+] Running Python DNS bruteforce with {len(words)} words")

    found = set()

    for word in words:
        candidate = f"{word}.{root_domain}"
        if resolve_domain(candidate):
            found.add(candidate)

    return found


def run_dnsgen(seed_domains, root_domain):
    if not tool_exists("dnsgen"):
        log("[!] dnsgen not found, skipping permutations")
        return set()

    if not seed_domains:
        return set()

    log("[+] Running dnsgen permutations")

    tmp = Path("/tmp/orphan-domain-seeds.txt")
    tmp.write_text("\n".join(sorted(seed_domains)), encoding="utf-8")

    out = run_cmd(["dnsgen", str(tmp)], timeout=180)
    return extract_domains(out, root_domain)


def resolve_candidates(domains):
    found = set()

    for domain in domains:
        if resolve_domain(domain):
            found.add(domain)

    return found


def run_reverse_dns(cidr, root_domain):
    log(f"[+] Running reverse DNS on {cidr}")
    found = set()

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        log(f"[!] Invalid CIDR skipped: {cidr}")
        return found

    for ip in net.hosts():
        ptr = reverse_dns(ip)
        if ptr:
            found.update(extract_domains(ptr, root_domain))

    return found


def run_katana(urls, root_domain):
    if not tool_exists("katana"):
        log("[!] katana not found, skipping crawl")
        return set()

    if not urls:
        return set()

    found = set()
    log("[+] Running katana crawl")

    for url in urls:
        out = run_cmd(["katana", "-silent", "-u", url], timeout=300)
        found.update(extract_domains(out, root_domain))

    return found


def parse_files(files, root_domain):
    found = set()

    for file in files:
        path = Path(file)
        if not path.exists():
            log(f"[!] File not found: {file}")
            continue

        log(f"[+] Parsing local file: {file}")
        text = path.read_text(errors="ignore")
        found.update(extract_domains(text, root_domain))

    return found


def query_dns_records(root_domain):
    log("[+] Checking common DNS records")

    found = set()

    for record in ["MX", "TXT", "NS", "SOA", "CNAME"]:
        for line in dig_record(root_domain, record):
            found.update(extract_domains(line, root_domain))

    common_hosts = [
        "www", "mail", "owa", "vpn", "portal", "remote", "legacy", "old",
        "dev", "test", "staging", "uat", "api", "admin", "sso", "idp",
        "citrix", "rdp", "intranet", "extranet", "files", "ftp", "git",
        "jira", "confluence", "grafana", "kibana", "jenkins", "build",
        "backup", "db", "sql", "mssql", "mysql", "postgres", "monitor",
        "status", "cdn", "assets", "static", "app", "apps", "demo",
    ]

    for host in common_hosts:
        candidate = f"{host}.{root_domain}"
        if resolve_domain(candidate):
            found.add(candidate)

    return found


def run_httpx(domains):
    if not tool_exists("httpx"):
        log("[!] httpx not found, skipping HTTP validation")
        return {}

    log("[+] Running httpx validation")

    tmp = Path("/tmp/orphan-domain-httpx-input.txt")
    tmp.write_text("\n".join(sorted(domains)), encoding="utf-8")

    out = run_cmd(
        [
            "httpx",
            "-silent",
            "-json",
            "-title",
            "-tech-detect",
            "-status-code",
            "-location",
            "-follow-redirects",
            "-l",
            str(tmp),
        ],
        timeout=600,
    )

    results = {}

    for line in out.splitlines():
        try:
            item = json.loads(line)
            host = item.get("input") or item.get("host")
            if not host:
                continue

            results[host] = {
                "url": item.get("url", ""),
                "status_code": item.get("status_code", ""),
                "title": item.get("title", ""),
                "tech": ",".join(item.get("tech", []))
                if isinstance(item.get("tech"), list)
                else "",
                "location": item.get("location", ""),
            }
        except Exception:
            continue

    return results


def check_domain(domain, httpx_data=None):
    ips = resolve_domain(domain)
    cname = dig_record(domain, "CNAME")
    mx = dig_record(domain, "MX")
    txt = dig_record(domain, "TXT")

    provider, provider_evidence = detect_provider(cname, ips)

    status = []

    if ips:
        status.append("RESOLVES")
    else:
        status.append("NO_A_RECORD")

    if cname:
        status.append("HAS_CNAME")

    if provider:
        status.append("PROVIDER_IDENTIFIED")

    joined_cname = " ".join(cname).lower()

    if any(indicator in joined_cname for indicator in PROVIDERS):
        status.append("CNAME_TO_CLOUD_SERVICE_REVIEW")

    if mx:
        status.append("HAS_MX")

    if txt:
        joined_txt = " ".join(txt).lower()
        if "spf" in joined_txt:
            status.append("HAS_SPF")
        if "dmarc" in joined_txt:
            status.append("HAS_DMARC_OR_POLICY_TXT")

    httpx_data = httpx_data or {}

    return {
        "domain": domain,
        "ips": ",".join(ips),
        "provider": provider,
        "provider_evidence": provider_evidence,
        "cname": " | ".join(cname),
        "mx": " | ".join(mx),
        "txt": " | ".join(txt[:3]),
        "http_url": httpx_data.get("url", ""),
        "http_status": httpx_data.get("status_code", ""),
        "http_title": httpx_data.get("title", ""),
        "http_tech": httpx_data.get("tech", ""),
        "http_location": httpx_data.get("location", ""),
        "status": ",".join(status),
    }


def write_csv(rows, output):
    fieldnames = [
        "domain",
        "ips",
        "provider",
        "provider_evidence",
        "cname",
        "mx",
        "txt",
        "http_url",
        "http_status",
        "http_title",
        "http_tech",
        "http_location",
        "status",
    ]

    with open(output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def clean_markdown(value):
    value = str(value or "").replace("|", "\\|").replace("\n", " ")
    return value[:140] + "..." if len(value) > 140 else value


def write_markdown(rows, output):
    headers = [
        "Domain",
        "Provider",
        "Evidence",
        "IPs",
        "CNAME",
        "HTTP",
        "Title",
        "Tech",
        "Status",
    ]

    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    clean_markdown(row.get("domain")),
                    clean_markdown(row.get("provider")),
                    clean_markdown(row.get("provider_evidence")),
                    clean_markdown(row.get("ips")),
                    clean_markdown(row.get("cname")),
                    clean_markdown(row.get("http_status")),
                    clean_markdown(row.get("http_title")),
                    clean_markdown(row.get("http_tech")),
                    clean_markdown(row.get("status")),
                ]
            )
            + " |"
        )

    Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_txt(domains, output):
    Path(output).write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")


def write_extra_outputs(rows, out_dir):
    live = []
    unresolved = []
    cloud_cnames = []
    provider_lines = {}

    for row in rows:
        domain = row.get("domain", "")
        provider = row.get("provider", "")
        status = row.get("status", "")
        cname = row.get("cname", "")
        http_url = row.get("http_url", "")

        if http_url:
            live.append(http_url)

        if "NO_A_RECORD" in status:
            unresolved.append(domain)

        if "CNAME_TO_CLOUD_SERVICE_REVIEW" in status:
            cloud_cnames.append(f"{domain} -> {cname}")

        if provider:
            provider_lines.setdefault(provider, []).append(domain)

    (out_dir / "live-hosts.txt").write_text("\n".join(sorted(live)) + "\n", encoding="utf-8")
    (out_dir / "unresolved.txt").write_text("\n".join(sorted(unresolved)) + "\n", encoding="utf-8")
    (out_dir / "cloud-cnames.txt").write_text("\n".join(sorted(cloud_cnames)) + "\n", encoding="utf-8")

    summary = []
    for provider in sorted(provider_lines):
        summary.append(f"## {provider}")
        summary.append("")
        for domain in sorted(provider_lines[provider]):
            summary.append(f"- {domain}")
        summary.append("")

    (out_dir / "provider-summary.md").write_text("\n".join(summary), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Passive and active orphan/subdomain discovery helper"
    )

    parser.add_argument("-d", "--domain", required=True, help="Root domain, e.g. example.com")

    parser.add_argument("-a", "--all", action="store_true", help="Run all available discovery modules")
    parser.add_argument("-o", "--output", help="Output CSV file")
    parser.add_argument("--md", help="Markdown table output")
    parser.add_argument("--txt", help="Plain text subdomain output")

    parser.add_argument("--cidr", action="append", default=[], help="CIDR for reverse DNS, can be used multiple times")
    parser.add_argument("--file", action="append", default=[], help="Parse local files for domains")
    parser.add_argument("--wordlist", help="DNS bruteforce wordlist")
    parser.add_argument("--crawl-url", action="append", default=[], help="URL to crawl with katana")

    parser.add_argument("--subfinder", action="store_true", help="Use subfinder if installed")
    parser.add_argument("--amass", action="store_true", help="Use amass passive if installed")
    parser.add_argument("--dnsgen", action="store_true", help="Generate permutations with dnsgen if installed")
    parser.add_argument("--httpx", action="store_true", help="Validate web services with httpx if installed")

    parser.add_argument("--no-crtsh", action="store_true", help="Disable crt.sh")
    parser.add_argument("--no-wayback", action="store_true", help="Disable Wayback CDX")
    parser.add_argument("--no-hackertarget", action="store_true", help="Disable HackerTarget")
    parser.add_argument("--no-rapiddns", action="store_true", help="Disable RapidDNS")
    parser.add_argument("--no-common-dns", action="store_true", help="Disable common DNS checks")

    args = parser.parse_args()

    if args.all:
        args.subfinder = True
        args.amass = True
        args.httpx = True
        args.dnsgen = True

        args.no_crtsh = False
        args.no_wayback = False
        args.no_hackertarget = False
        args.no_rapiddns = False
        args.no_common_dns = False

        default_wordlists = [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
            "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        ]

        if not args.wordlist:
            for wordlist in default_wordlists:
                if Path(wordlist).exists():
                    args.wordlist = wordlist
                    break

        if not args.crawl_url:
            args.crawl_url = [
                f"https://{args.domain}",
                f"http://{args.domain}",
            ]

    root_domain = args.domain.lower().strip(".")
    discovered = set()

    out_dir = Path(root_domain)
    out_dir.mkdir(exist_ok=True)

    if not args.output:
        args.output = str(out_dir / "orphan-domains.csv")

    if not args.md:
        args.md = str(out_dir / "orphan-domains.md")

    if not args.txt:
        args.txt = str(out_dir / "all-subdomains.txt")

    log(f"[+] Target domain: {root_domain}")
    log(f"[+] Output directory: {out_dir}")

    if args.all:
        log("[+] Running in ALL mode")
        if args.wordlist:
            log(f"[+] Using wordlist: {args.wordlist}")

    if not args.no_crtsh:
        discovered.update(query_crtsh(root_domain))

    if not args.no_wayback:
        discovered.update(query_wayback(root_domain))

    if not args.no_hackertarget:
        discovered.update(query_hackertarget(root_domain))

    if not args.no_rapiddns:
        discovered.update(query_rapiddns(root_domain))

    if not args.no_common_dns:
        discovered.update(query_dns_records(root_domain))

    if args.subfinder:
        discovered.update(run_subfinder(root_domain))

    if args.amass:
        discovered.update(run_amass(root_domain))

    for cidr in args.cidr:
        discovered.update(run_reverse_dns(cidr, root_domain))

    if args.file:
        discovered.update(parse_files(args.file, root_domain))

    if args.crawl_url:
        discovered.update(run_katana(args.crawl_url, root_domain))

    if args.wordlist:
        discovered.update(run_dns_bruteforce(root_domain, args.wordlist))

    if args.dnsgen:
        permutations = run_dnsgen(discovered, root_domain)
        discovered.update(resolve_candidates(permutations))

    discovered = {
        d for d in discovered
        if d == root_domain or d.endswith("." + root_domain)
    }

    log(f"[+] Total discovered domains: {len(discovered)}")

    write_txt(discovered, args.txt)
    log(f"[+] Written plain list to: {args.txt}")

    httpx_results = run_httpx(discovered) if args.httpx else {}

    rows = []
    for domain in sorted(discovered):
        rows.append(check_domain(domain, httpx_results.get(domain, {})))

    write_csv(rows, args.output)
    log(f"[+] Written CSV results to: {args.output}")

    write_markdown(rows, args.md)
    log(f"[+] Written Markdown results to: {args.md}")

    write_extra_outputs(rows, out_dir)
    log(f"[+] Written extra outputs to: {out_dir}")


if __name__ == "__main__":
    main()
