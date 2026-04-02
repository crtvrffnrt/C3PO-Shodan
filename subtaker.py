#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from html import unescape


TXT_PATTERNS = {
    "google-site-verification": "Google site verification",
    "ms=": "Microsoft verification",
    "atlassian-domain-verification": "Atlassian verification",
    "facebook-domain-verification": "Facebook verification",
    "globalsign-domain-verification": "GlobalSign verification",
    "google._domainkey": "Google DKIM hint",
    "spf1": "SPF policy",
    "dmarc": "DMARC policy",
    "amazonses": "Amazon SES verification",
    "zoho-verification": "Zoho verification",
    "dropbox-domain-verification": "Dropbox verification",
    "apple-domain-verification": "Apple verification",
}

HIGH_RISK_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    2375: "Docker API",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9000: "Admin / Sonar / PHP-FPM adjacencies",
    9200: "Elasticsearch",
    9300: "Elasticsearch transport",
    11211: "Memcached",
    27017: "MongoDB",
}

MULTI_LEVEL_SUFFIXES = {
    "ac.uk",
    "co.jp",
    "co.nz",
    "com.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.mx",
    "com.sg",
    "com.tr",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
}


def log(msg: str, debug: bool = False, stderr: bool = False) -> None:
    stream = sys.stderr if stderr else sys.stdout
    if debug:
        print(msg, file=stream)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip().lower()
    if not value:
        return ""
    if "://" in value:
        value = urllib.parse.urlparse(value).netloc or value
    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]
    if ":" in value and value.count(":") == 1 and "." in value:
        value = value.split(":", 1)[0]
    if value.startswith("*."):
        value = value[2:]
    return value.strip(".")


def core_domain(domain: str) -> str:
    parts = [part for part in normalize_domain(domain).split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_LEVEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    return cleaned or "target"


def is_probable_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_probable_hostname(value: str) -> bool:
    if not value:
        return False
    value = normalize_domain(value)
    if not value or is_probable_ip(value):
        return False
    return bool(re.fullmatch(r"[a-z0-9*_.-]+", value)) and "." in value


def is_in_scope(host: str, domain: str) -> bool:
    host = normalize_domain(host)
    domain = normalize_domain(domain)
    return host == domain or host.endswith(f".{domain}")


def load_shodan_key() -> tuple[str, str]:
    env_key = os.environ.get("SHODANAPI", "").strip()
    if env_key:
        return env_key, "env"

    key_path = os.path.expanduser("~/.shodan/api_key")
    if os.path.isfile(key_path):
        with open(key_path, "r", encoding="utf-8") as handle:
            file_key = handle.read().strip()
        if file_key:
            return file_key, key_path

    raise RuntimeError("No Shodan API key found in SHODANAPI or ~/.shodan/api_key")


def redact_url(url: str) -> str:
    if "key=" not in url:
        return url
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    safe = [(key, "REDACTED" if key == "key" else value) for key, value in query]
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(safe), parsed.fragment)
    )


def shodan_get_json(url: str, debug: bool, timeout: int = 20) -> tuple[dict, int]:
    delay = 1
    for attempt in range(1, 6):
        log(f"[debug] GET {redact_url(url)} (attempt {attempt}/5)", debug)
        cmd = [
            "curl",
            "-s",
            "-L",
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout + 10),
            "-w", "\n%{http_code}",
            url
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = result.stdout.splitlines()
            if not output:
                status = 0
                body = ""
            else:
                status_str = output[-1].strip()
                status = int(status_str) if status_str.isdigit() else 0
                body = "\n".join(output[:-1])
        except Exception as exc:
            log(f"[debug] Request error for {redact_url(url)}: {exc}", debug)
            return {}, 0

        if status == 200:
            try:
                return json.loads(body), status
            except json.JSONDecodeError:
                log(f"[debug] Invalid JSON from {redact_url(url)}", debug)
                return {}, status

        if status in (429, 500, 502, 503, 504):
            time.sleep(delay)
            delay *= 2
            continue

        log(f"[debug] HTTP {status} for {redact_url(url)}", debug)
        return {}, status

    return {}, 429


def load_provider_fragments(path: str) -> list[str]:
    fragments = []
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip().lower().rstrip(".")
            if line:
                fragments.append(line)
    return fragments


def provider_category(fragment: str) -> str:
    fragment = fragment.lower()
    if "trafficmanager" in fragment:
        return "Traffic Manager"
    if "azurefd" in fragment:
        return "Front Door"
    if "azurewebsites" in fragment:
        return "App Service"
    if "azurestaticapps" in fragment:
        return "Static App"
    if "cloudapp" in fragment:
        return "Azure VM / Cloud Service"
    if "web.core.windows.net" in fragment:
        return "Static Website"
    if ".core.windows.net" in fragment:
        return "Azure Storage"
    if "github.io" in fragment:
        return "GitHub Pages"
    if "heroku" in fragment:
        return "Heroku"
    if "pages.dev" in fragment:
        return "Cloudflare Pages"
    if "fastly" in fragment:
        return "Fastly"
    if "netlify" in fragment:
        return "Netlify"
    return "Provider-linked"


def normalize_dns_owner(domain: str, raw_owner: str) -> str:
    owner = (raw_owner or "").strip()
    if not owner or owner == "@":
        return domain
    owner = normalize_domain(owner)
    if not owner:
        return domain
    if owner == domain or owner.endswith(f".{domain}"):
        return owner
    if "." not in owner:
        return f"{owner}.{domain}"
    return owner


def explode_record_value(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        values = value
    else:
        values = [value]
    normalized = []
    for item in values:
        text = str(item).strip()
        if text:
            normalized.append(text.rstrip("."))
    return normalized


def normalize_record(domain: str, entry: dict, source: str) -> list[dict]:
    record_type = str(entry.get("type") or entry.get("record_type") or "").upper().strip()
    owner = (
        entry.get("rrname")
        or entry.get("hostname")
        or entry.get("name")
        or entry.get("host")
        or entry.get("subdomain")
        or entry.get("domain")
        or "@"
    )
    owner = normalize_dns_owner(domain, str(owner))
    last_seen = entry.get("last_seen") or entry.get("timestamp") or entry.get("date") or ""
    values = explode_record_value(entry.get("value") or entry.get("answer") or entry.get("data"))
    if not values:
        values = [""]
    records = []
    for value in values:
        records.append(
            {
                "hostname": owner,
                "type": record_type or "UNKNOWN",
                "value": value,
                "last_seen": str(last_seen),
                "source": source,
            }
        )
    return records


def fetch_shodan_dns(domain: str, api_key: str, page_limit: int, include_history: bool, debug: bool) -> tuple[list[dict], dict]:
    records = []
    hostname_sources: dict[str, set[str]] = defaultdict(set)
    modes = [("current", False)]
    if include_history:
        modes.append(("history", True))

    for label, history_flag in modes:
        page_signatures = set()
        for page in range(1, page_limit + 1):
            url = (
                "https://api.shodan.io/dns/domain/"
                f"{urllib.parse.quote(domain)}?key={api_key}&page={page}&history={'true' if history_flag else 'false'}"
            )
            payload, status = shodan_get_json(url, debug)
            if status != 200 or not payload:
                break

            raw_records = payload.get("data") or []
            subdomains = payload.get("subdomains") or []
            signature = (
                len(raw_records),
                tuple(sorted(str(item) for item in subdomains[:20])),
            )
            if signature in page_signatures:
                break
            page_signatures.add(signature)

            if not raw_records and page > 1:
                break

            for subdomain in subdomains:
                host = normalize_dns_owner(domain, str(subdomain))
                if is_in_scope(host, domain):
                    hostname_sources[host].add(f"shodan_dns_{label}")

            for entry in raw_records:
                if not isinstance(entry, dict):
                    continue
                for record in normalize_record(domain, entry, f"shodan_dns_{label}"):
                    records.append(record)
                    if is_in_scope(record["hostname"], domain):
                        hostname_sources[record["hostname"]].add(f"shodan_dns_{label}")
                    value = normalize_domain(record["value"])
                    if is_in_scope(value, domain):
                        hostname_sources[value].add(f"shodan_dns_{label}")

    hostname_sources[domain].add("target")
    return records, {host: sorted(values) for host, values in hostname_sources.items()}


def fetch_crtsh_hosts(domain: str, timeout: int, debug: bool) -> list[str]:
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    cmd = [
        "curl",
        "-s",
        "-L",
        "--connect-timeout", str(timeout),
        "--max-time", str(timeout + 20),
        "-H", "User-Agent: C3PO-shodan/1.0",
        url
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return []
        body = result.stdout
        if not body:
            return []
        payload = json.loads(body)
    except Exception as exc:
        log(f"[debug] crt.sh lookup failed: {exc}", debug)
        return []

    hosts = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        for field in ("common_name", "name_value"):
            raw_value = entry.get(field) or ""
            for token in str(raw_value).splitlines():
                host = normalize_domain(token)
                if host and is_in_scope(host, domain):
                    hosts.add(host)
    return sorted(hosts)


def resolve_host_ips(hostname: str) -> list[str]:
    ips = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP):
            if family == socket.AF_INET:
                ips.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ips.add(sockaddr[0])
    except Exception:
        return []
    return sorted(ips, key=lambda value: (ipaddress.ip_address(value).version, ipaddress.ip_address(value)))


def reverse_lookup(ip: str) -> list[str]:
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
    except Exception:
        return []
    names = {normalize_domain(host)}
    for alias in aliases:
        normalized = normalize_domain(alias)
        if normalized:
            names.add(normalized)
    return sorted(name for name in names if name)


def extract_title(content: bytes) -> str:
    if not content:
        return ""
    text = content.decode("utf-8", errors="replace")
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:160]


def probe_http(hostname: str, timeout: int) -> dict:
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        cmd = [
            "curl",
            "-s",
            "-L",
            "-i",
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout + 5),
            "--max-redirs", "5",
            "-k",
            "-H", "User-Agent: C3PO-shodan/1.0",
            url
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, check=False)
            if result.returncode != 0:
                continue
            
            raw_output = result.stdout
            headers_part, _, body_part = raw_output.partition(b"\r\n\r\n")
            if not body_part and not headers_part.startswith(b"HTTP/"):
                headers_part, _, body_part = raw_output.partition(b"\n\n")

            headers_text = headers_part.decode("utf-8", errors="replace")
            status_match = re.search(r"HTTP/\d\.\d\s+(\d+)", headers_text)
            status_code = int(status_match.group(1)) if status_match else 0
            
            server = ""
            content_type = ""
            for line in headers_text.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                elif line.lower().startswith("content-type:"):
                    content_type = line.split(":", 1)[1].strip()

            return {
                "probed": True,
                "reachable": True,
                "scheme": scheme,
                "url": url,
                "status_code": status_code,
                "title": extract_title(body_part[:131072]),
                "server": server,
                "content_type": content_type,
            }
        except Exception:
            continue

    return {
        "probed": True,
        "reachable": False,
        "scheme": "",
        "url": "",
        "status_code": 0,
        "title": "",
        "server": "",
        "content_type": "",
    }


def fetch_shodan_api_info(api_key: str, debug: bool) -> dict:
    url = f"https://api.shodan.io/api-info?key={api_key}"
    payload, status = shodan_get_json(url, debug)
    return payload if status == 200 else {}


def fetch_shodan_host(ip: str, api_key: str, debug: bool) -> dict:
    url = f"https://api.shodan.io/shodan/host/{urllib.parse.quote(ip)}?key={api_key}&minify=false"
    payload, status = shodan_get_json(url, debug)
    return payload if status == 200 else {}


def summarize_shodan_services(payload: dict) -> dict:
    ports = sorted({int(port) for port in payload.get("ports", []) if str(port).isdigit()})
    data = payload.get("data") or []
    services = []
    products = set()
    for entry in data:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        product = entry.get("product") or ""
        version = entry.get("version") or ""
        transport = entry.get("transport") or ""
        title = ""
        if isinstance(entry.get("http"), dict):
            title = entry["http"].get("title") or ""
        if product:
            products.add(product.strip())
        services.append(
            {
                "port": int(port) if isinstance(port, int) else port,
                "transport": transport,
                "product": product.strip(),
                "version": version.strip(),
                "http_title": title.strip(),
            }
        )

    vulns = payload.get("vulns") or {}
    if isinstance(vulns, dict):
        vuln_list = sorted(vulns.keys())
    elif isinstance(vulns, list):
        vuln_list = sorted(str(item) for item in vulns)
    else:
        vuln_list = []

    return {
        "ports": ports,
        "products": sorted(product for product in products if product),
        "services": services[:25],
        "vulns": vuln_list,
        "hostnames": sorted({normalize_domain(item) for item in payload.get("hostnames", []) if item}),
        "domains": sorted({normalize_domain(item) for item in payload.get("domains", []) if item}),
        "tags": sorted(str(item) for item in payload.get("tags", []) if item),
        "org": str(payload.get("org") or ""),
        "isp": str(payload.get("isp") or ""),
        "asn": str(payload.get("asn") or ""),
        "country": str(payload.get("country_name") or ""),
        "city": str(payload.get("city") or ""),
        "os": str(payload.get("os") or ""),
        "last_update": str(payload.get("last_update") or ""),
    }


def interesting_txt_findings(hostname: str, records: list[dict]) -> list[dict]:
    findings = []
    for record in records:
        if record.get("type") != "TXT":
            continue
        value_raw = record.get("value", "")
        value_lower = value_raw.lower()
        for pattern, label in TXT_PATTERNS.items():
            if pattern in value_lower:
                findings.append(
                    {
                        "hostname": hostname,
                        "label": label,
                        "match": pattern,
                        "value": value_raw,
                        "source": record.get("source", ""),
                    }
                )
        if "v=spf1" in value_lower and "~all" in value_lower:
            findings.append(
                {
                    "hostname": hostname,
                    "label": "Risky SPF Softfail",
                    "match": "~all",
                    "value": value_raw,
                    "source": record.get("source", ""),
                    "recommendation": "Change ~all to -all to prevent email spoofing and perform an Email Security Audit."
                }
            )
    return findings


def provider_matches(cname_targets: list[str], fragments: list[str]) -> list[dict]:
    matches = []
    for target in cname_targets:
        normalized = normalize_domain(target)
        for fragment in fragments:
            if normalized == fragment or normalized.endswith(f".{fragment}"):
                matches.append(
                    {
                        "target": normalized,
                        "fragment": fragment,
                        "category": provider_category(fragment),
                    }
                )
    unique = {(match["target"], match["fragment"], match["category"]): match for match in matches}
    return sorted(unique.values(), key=lambda item: (item["category"], item["target"]))


def compute_takeover_signal(current_ips: list[str], http_info: dict, providers: list[dict]) -> tuple[bool, list[str]]:
    reasons = []
    if not providers:
        return False, reasons

    if not current_ips:
        reasons.append("Provider-linked CNAME without a current A/AAAA resolution")
    if http_info.get("probed") and not http_info.get("reachable"):
        reasons.append("HTTP/S probe failed for provider-linked hostname")

    candidate = bool(reasons)
    return candidate, reasons


def sort_hostnames(hostnames: list[str], domain: str) -> list[str]:
    return sorted(
        set(hostnames),
        key=lambda host: (0 if host == domain else 1, host.count("."), host),
    )


def safe_int(value, default: int) -> int:
    try:
        return int(str(value))
    except Exception:
        return default


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Collect Shodan-centric attack-surface intelligence for a domain.",
    )
    parser.add_argument("--domain", required=True, help="Target root domain.")
    parser.add_argument("--output", required=True, help="Output JSON path.")
    parser.add_argument("--provider-fragments", required=True, help="Provider fragment list.")
    parser.add_argument("--dns-page-limit", type=int, default=4, help="Maximum Shodan DNS pages per mode.")
    parser.add_argument("--host-enrichment-limit", type=int, default=30, help="Max unique IPs to enrich via Shodan.")
    parser.add_argument("--web-timeout", type=int, default=10, help="HTTP probe timeout seconds.")
    parser.add_argument("--max-web-probes", type=int, default=40, help="Maximum hostnames to probe over HTTP/S.")
    parser.add_argument("--ct-timeout", type=int, default=20, help="crt.sh timeout seconds.")
    parser.add_argument("--include-crtsh", action="store_true", help="Enrich with crt.sh hostnames.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    return parser


def run_domain_shodan_checks(
    domain: str,
    provider_fragments: str,
    dns_page_limit: int = 4,
    host_enrichment_limit: int = 30,
    web_timeout: int = 10,
    max_web_probes: int = 40,
    ct_timeout: int = 20,
    include_crtsh: bool = True,
    debug: bool = False,
) -> dict:
    class MockArgs:
        def __init__(self):
            self.domain = domain
            self.provider_fragments = provider_fragments
            self.dns_page_limit = dns_page_limit
            self.host_enrichment_limit = host_enrichment_limit
            self.web_timeout = web_timeout
            self.max_web_probes = max_web_probes
            self.ct_timeout = ct_timeout
            self.include_crtsh = include_crtsh
            self.debug = debug
            self.output = None

    return _run_core_logic(MockArgs())


def _run_core_logic(args) -> dict:
    target_domain = core_domain(args.domain)
    if not target_domain:
        raise ValueError("Invalid domain.")

    try:
        shodan_key, shodan_key_source = load_shodan_key()
    except RuntimeError as exc:
        raise RuntimeError(f"Shodan key error: {exc}")

    provider_fragment_list = load_provider_fragments(args.provider_fragments)
    shodan_info = fetch_shodan_api_info(shodan_key, args.debug)
    dns_records, hostname_sources = fetch_shodan_dns(
        target_domain,
        shodan_key,
        max(args.dns_page_limit, 1),
        include_history=True,
        debug=args.debug,
    )

    if args.include_crtsh:
        for host in fetch_crtsh_hosts(target_domain, args.ct_timeout, args.debug):
            hostname_sources.setdefault(host, []).append("crtsh")

    hostname_source_sets: dict[str, set[str]] = defaultdict(set)
    for host, sources in hostname_sources.items():
        for source in sources:
            hostname_source_sets[normalize_domain(host)].add(source)

    in_scope_hosts = sort_hostnames(
        [host for host in hostname_source_sets if is_in_scope(host, target_domain)],
        target_domain,
    )

    record_index: dict[str, list[dict]] = defaultdict(list)
    for record in dns_records:
        record_index[record["hostname"]].append(record)

    ip_host_cache: dict[str, dict] = {}
    reverse_cache: dict[str, list[str]] = {}
    additional_hosts = set()

    def get_ip_summary(ip: str) -> dict:
        if ip in ip_host_cache:
            return ip_host_cache[ip]
        payload = fetch_shodan_host(ip, shodan_key, args.debug)
        summary = summarize_shodan_services(payload) if payload else {
            "ports": [], "products": [], "services": [], "vulns": [], "hostnames": [],
            "domains": [], "tags": [], "org": "", "isp": "", "asn": "", "country": "",
            "city": "", "os": "", "last_update": "",
        }
        ip_host_cache[ip] = summary
        return summary

    host_profiles = []
    takeover_candidates = []
    interesting_txt = []
    aggregated_ips = {}

    web_probe_count = 0
    max_web_probes_limit = max(1, getattr(args, "max_web_probes", 40))

    for host in in_scope_hosts[: args.host_enrichment_limit]:
        host_records = record_index.get(host, [])
        historical_ips = sorted(list(set(rec["value"] for rec in host_records if rec["type"] in ("A", "AAAA") and is_probable_ip(rec["value"]))))
        current_ips = resolve_host_ips(host)
        cname_targets = sorted(list(set(rec["value"] for rec in host_records if rec["type"] == "CNAME")))
        txt_records = sorted(list(set(rec["value"] for rec in host_records if rec["type"] == "TXT")))
        mx_records = sorted(list(set(rec["value"] for rec in host_records if rec["type"] == "MX")))
        ns_records = sorted(list(set(rec["value"] for rec in host_records if rec["type"] == "NS")))

        txt_hits = interesting_txt_findings(host, host_records)
        interesting_txt.extend(txt_hits)

        provider_links = provider_matches(cname_targets, provider_fragment_list)

        http_info = {"reachable": False, "url": "", "status": 0, "title": "", "server": "", "redirect_url": ""}
        if web_probe_count < max_web_probes_limit:
            http_info = probe_http(host, args.web_timeout)
            if http_info["reachable"]:
                web_probe_count += 1

        takeover_flag, takeover_reasons = compute_takeover_signal(current_ips, http_info, provider_links)

        union_ports, union_products, union_vulns, reverse_names, cohost_indicators = set(), set(), set(), set(), set()
        ip_summaries = {}

        for ip in current_ips:
            details = get_ip_summary(ip)
            ip_summaries[ip] = details
            union_ports.update(details["ports"])
            union_products.update(details["products"])
            union_vulns.update(details["vulns"])
            reverse_names.update(details["hostnames"])

            if ip not in aggregated_ips:
                aggregated_ips[ip] = {
                    "version": 4 if ":" not in ip else 6,
                    "network_hint": f"{ip.rsplit('.', 1)[0]}.0/24" if ":" not in ip else f"{ip.rsplit(':', 1)[0]}::/64",
                    "hostnames": {host}, "reverse_hostnames": set(details["hostnames"]), "ports": set(details["ports"]),
                    "products": set(details["products"]), "vulns": set(details["vulns"]), "tags": set(details["tags"]),
                    "org": details["org"], "isp": details["isp"], "asn": details["asn"], "country": details["country"],
                    "city": details["city"], "os": details["os"], "shodan_last_update": details["last_update"], "cohost_indicators": set(),
                }
            else:
                aggregated_ips[ip]["hostnames"].add(host)

            for other in details["hostnames"]:
                if other != host and is_in_scope(other, target_domain):
                    additional_hosts.add(other)
                elif other != host:
                    cohost_indicators.add(other)
                    aggregated_ips[ip]["cohost_indicators"].add(other)

        score, risk_factors = 0, []
        if http_info["reachable"]: score += 5; risk_factors.append("Active HTTP/S service")
        if provider_links: score += 10; risk_factors.append(f"Provider-linked CNAME chain ({len(provider_links)})")
        if takeover_flag: score += 24; risk_factors.extend(takeover_reasons)
        if union_ports: score += min(16, len(union_ports) * 2); risk_factors.append(f"Shodan observed {len(union_ports)} open port(s)")
        dangerous = sorted(port for port in union_ports if port in HIGH_RISK_PORTS)
        if dangerous: score += min(20, 6 + len(dangerous) * 2); risk_factors.append("High-signal exposed services: " + ", ".join(f"{port}/{HIGH_RISK_PORTS[port]}" for port in dangerous[:6]))
        if union_vulns: score += 25; risk_factors.append(f"Shodan vulnerability hints: {', '.join(sorted(union_vulns)[:4])}")
        if txt_hits: score += min(8, len(txt_hits) * 2); risk_factors.append(f"Interesting TXT evidence ({len(txt_hits)})")
        if cohost_indicators: score += 4; risk_factors.append(f"Co-hosted external names observed on related IP(s): {len(cohost_indicators)}")

        risk_level = "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 25 else "low"

        host_profiles.append({
            "hostname": host, "sources": sorted(hostname_source_sets.get(host, [])), "current_ips": current_ips,
            "historical_ips": historical_ips, "cname_targets": cname_targets, "mx_records": mx_records,
            "ns_records": ns_records, "txt_records": txt_records, "txt_findings": txt_hits, "provider_matches": provider_links,
            "http": http_info, "reverse_hostnames": sorted(name for name in reverse_names if name and name != host),
            "cohost_indicators": sorted(cohost_indicators)[:25], "ports": sorted(union_ports), "products": sorted(union_products),
            "vulns": sorted(union_vulns), "shodan_services": ip_summaries, "takeover_candidate": takeover_flag,
            "takeover_reasons": takeover_reasons, "risk_score": score, "risk_level": risk_level, "risk_factors": risk_factors,
        })

        if takeover_flag:
            takeover_candidates.append({"hostname": host, "provider_matches": provider_links, "reasons": takeover_reasons, "current_ips": current_ips})

    all_hosts_with_scores = sorted(host_profiles, key=lambda item: (-item["risk_score"], item["hostname"]))
    host_profiles = all_hosts_with_scores[:10]

    ip_assets = []
    for ip, details in sorted(aggregated_ips.items(), key=lambda item: (ipaddress.ip_address(item[0]).version, ipaddress.ip_address(item[0]))):
        ip_assets.append({
            "ip": ip, "version": details["version"], "network_hint": details["network_hint"], "hostnames": sorted(details["hostnames"]),
            "reverse_hostnames": sorted(details["reverse_hostnames"]), "ports": sorted(details["ports"]), "products": sorted(details["products"]),
            "vulns": sorted(details["vulns"]), "tags": sorted(details["tags"]), "org": details["org"], "isp": details["isp"], "asn": details["asn"],
            "country": details["country"], "city": details["city"], "os": details["os"], "shodan_last_update": details["shodan_last_update"],
            "cohost_indicators": sorted(details["cohost_indicators"])[:20],
        })

    network_ranges = defaultdict(lambda: {"ips": 0, "hosts": set()})
    for ip_asset in ip_assets:
        network_ranges[ip_asset["network_hint"]]["ips"] += 1
        network_ranges[ip_asset["network_hint"]]["hosts"].update(ip_asset["hostnames"])

    interesting_txt = list({(item["hostname"], item["label"], item["value"]): item for item in interesting_txt}.values())
    interesting_txt.sort(key=lambda item: (item["hostname"], item["label"], item["value"]))

    summary = {
        "host_count": len(host_profiles), "web_host_count": sum(1 for host in host_profiles if host["http"].get("reachable")),
        "ip_count": len(ip_assets), "takeover_candidate_count": len(takeover_candidates), "txt_hit_count": len(interesting_txt),
        "critical_count": sum(1 for host in host_profiles if host["risk_level"] == "critical"),
        "high_count": sum(1 for host in host_profiles if host["risk_level"] == "high"),
        "medium_count": sum(1 for host in host_profiles if host["risk_level"] == "medium"),
        "low_count": sum(1 for host in host_profiles if host["risk_level"] == "low"),
        "original_total_hosts": len(all_hosts_with_scores)
    }

    return {
        "target": {"input": normalize_domain(args.domain), "core_domain": target_domain, "slug": slugify(target_domain), "generated_at": now_iso()},
        "api": {"shodan_key_source": shodan_key_source, "shodan_api_info": shodan_info},
        "config": {"dns_page_limit": safe_int(args.dns_page_limit, 4), "host_enrichment_limit": safe_int(args.host_enrichment_limit, 30), "web_timeout": safe_int(args.web_timeout, 10), "max_web_probes": getattr(args, "max_web_probes", 40), "crtsh_enabled": bool(args.include_crtsh)},
        "summary": summary,
        "discoveries": {
            "dns_records": sorted(dns_records, key=lambda item: (item["hostname"], item["type"], item["value"], item["source"])),
            "interesting_txt": interesting_txt, "takeover_candidates": takeover_candidates,
            "network_ranges": [{"network_hint": network, "ip_count": details["ips"], "host_count": len(details["hosts"]), "hostnames": sorted(details["hosts"])} for network, details in sorted(network_ranges.items())],
        },
        "hosts": host_profiles, "ips": ip_assets,
    }


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        output = _run_core_logic(args)
    except Exception as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1
    if getattr(args, "output", None):
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
            handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
