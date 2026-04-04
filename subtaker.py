#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


def log_err(msg: str, debug: bool) -> None:
    if debug:
        print(msg)
    else:
        print(msg, file=sys.stderr)


def log_dbg(msg: str, debug: bool) -> None:
    if debug:
        print(f"[debug] {msg}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="subtaker.py",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        description=(
            "Query Shodan DNS data for target domains and match results against\n"
            "suffix fragments. Emits a live table to stdout and optionally writes\n"
            "JSON/CSV output files."
        ),
        epilog=(
            "Examples:\n"
            "  ./subtaker.py -i scope.txt -d target-domainfragments.txt\n"
            "  ./subtaker.py -i scope.txt -d target-domainfragments.txt -O json --output out.json\n"
        ),
    )
    parser.add_argument("-i", dest="input_file", help="Input scope file (required).")
    parser.add_argument("-d", dest="fragments_file", help="Suffix fragments file (required).")
    parser.add_argument(
        "-O",
        dest="out_format",
        default="table",
        choices=["table", "json", "csv"],
        help="Output file format when --output is used. Default: table.",
    )
    parser.add_argument("--output", dest="out_file", default="", help="Write JSON/CSV to this file.")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument(
        "-scope",
        dest="scope",
        choices=["trafficmanager", "storage", "websites", "frontdoor"],
        help="Filter CNAME targets by product (trafficmanager, storage, websites, frontdoor).",
    )
    parser.add_argument("-h", "--help", action="store_true", dest="help_flag", help="Show this help and exit.")
    return parser


def print_help_if_requested(parser: argparse.ArgumentParser, argv) -> None:
    if any(arg in ("-h", "--help") for arg in argv):
        parser.print_help()
        sys.exit(0)


def read_lines(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            yield line


def load_suffixes(path: str):
    suffixes = []
    for line in read_lines(path):
        normalized = "".join(line.split()).lower().rstrip(".")
        if normalized:
            suffixes.append(normalized)
    return suffixes


def normalize_domain(raw: str) -> str:
    if not raw: return ""
    value = raw.strip()
    if "://" in value:
        value = urllib.parse.urlparse(value).netloc or value
    value = value.split("/", 1)[0].strip().lower().rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def core_domain(domain: str) -> str:
    parts = [part for part in domain.split(".") if part]
    if len(parts) <= 2:
        return domain
    sld_tlds = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "co.nz", "com.au", "net.au",
        "org.au", "co.jp", "com.br", "com.mx", "com.tr", "com.cn", "com.hk", "com.sg",
    }
    last_two = ".".join(parts[-2:])
    if last_two in sld_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def is_suffix_match(host: str, suffixes) -> bool:
    if not host:
        return False
    host = host.rstrip(".").lower()
    for suffix in suffixes:
        if host == suffix or host.endswith(f".{suffix}"):
            return True
    return False


def redact_url(url: str) -> str:
    if "key=" not in url:
        return url
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    redacted = [(k, "REDACTED" if k == "key" else v) for k, v in query]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(redacted), parts.fragment)
    )


def shodan_api_info(api_key: str, debug: bool) -> tuple[str, int]:
    url = f"https://api.shodan.io/api-info?key={api_key}"
    body, status, _ = shodan_get(url, debug)
    return body, status


def shodan_get(url: str, debug: bool, passthrough: any = None) -> tuple[str, int, any]:
    attempt = 0
    max_attempts = 5
    delay = 1
    while attempt < max_attempts:
        attempt += 1
        log_dbg(f"Shodan request (attempt {attempt}/{max_attempts}): {redact_url(url)}", debug)
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                status = resp.getcode()
        except urllib.error.HTTPError as exc:
            status = exc.code
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            log_dbg(f"Request failed: {redact_url(url)}", debug)
            return ("", 0, passthrough)

        if status == 200:
            log_dbg(f"Shodan response 200 for: {redact_url(url)}", debug)
            return (body, status, passthrough)

        if status == 429 or "rate limit" in body.lower():
            log_dbg(f"Rate limited (status {status}); backing off {delay}s", debug)
            time.sleep(delay)
            delay *= 2
            continue

        log_dbg(f"Shodan API error ({status}): {redact_url(url)}", debug)
        return ("", status, passthrough)

    log_dbg(f"Shodan API rate limit exceeded: {redact_url(url)}", debug)
    return ("", 429, passthrough)


def load_shodan_key_file() -> str:
    path = os.path.expanduser("~/.shodan/api_key")
    if not os.path.isfile(path):
        return ""
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read().strip()


FRONTDOOR_SUFFIXES = ("azurefd.net",)
SCOPE_SUFFIXES = {
    "trafficmanager": ("trafficmanager.net",),
    "storage": ("core.windows.net",),
    "websites": ("azurewebsites.net",),
    "frontdoor": FRONTDOOR_SUFFIXES,
}
def resolve_httpx_binary() -> str:
    candidates = []
    env_path = os.environ.get("HTTPX_BIN", "").strip()
    if env_path:
        candidates.append(env_path)

    home = Path.home()
    candidates.extend(
        [
            str(home / ".pdtm" / "go" / "bin" / "httpx"),
            str(home / "go" / "bin" / "httpx"),
            shutil.which("httpx") or "",
            "/usr/local/bin/httpx",
            "/usr/bin/httpx",
        ]
    )

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


HTTPX_STATE = {
    "path": resolve_httpx_binary(),
    "disabled_reason": "",
}


def extract_hostname(raw: str) -> str:
    host = raw.strip().lower()
    if not host:
        return ""
    if "://" in host:
        host = urllib.parse.urlparse(host).netloc or host
    host = host.split("/", 1)[0]
    host = host.split("#", 1)[0]
    host = host.split("?", 1)[0]
    return host.strip().rstrip(".")


def print_header() -> None:
    print(f"{'DOMAIN':<30} {'SUBDOMAIN':<45} VALUE")
    print(f"{'------':<30} {'---------':<45} -----")


def init_output_writer(args):
    if not args.out_file or args.out_format not in ("json", "csv"):
        return (None, None)
    if args.out_format == "csv":
        handle = open(args.out_file, "w", encoding="utf-8", newline="")
        writer = csv.writer(handle)
        writer.writerow(["domain", "subdomain", "value"])
        handle.flush()

        def emit(item):
            writer.writerow([item["domain"], item["subdomain"], item["value"]])
            handle.flush()

        return (handle, emit)

    handle = open(args.out_file, "w", encoding="utf-8")
    close_str = "\n]\n"
    handle.write("[\n]\n")
    handle.flush()
    state = {"first": True, "pos": len("[\n")}

    def emit(item):
        payload = json.dumps(item, separators=(",", ":"))
        handle.seek(state["pos"])
        prefix = "" if state["first"] else ",\n"
        handle.write(f"{prefix}{payload}")
        handle.write(close_str)
        handle.flush()
        state["pos"] = handle.tell() - len(close_str)
        state["first"] = False

    return (handle, emit)


def probe_http_simple(hostname: str) -> dict:
    """Simple HTTP/S probe using urllib."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, headers={"User-Agent": "C3PO-shodan/1.0"})
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                status = resp.getcode()
                content = resp.read(16384).decode("utf-8", errors="replace")
                title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else ""
                return {
                    "probed": True, "reachable": True, "scheme": scheme, "url": url,
                    "status_code": status, "title": title[:100]
                }
        except Exception:
            continue
    return {"probed": True, "reachable": False, "scheme": "", "url": "", "status_code": 0, "title": ""}


def choose_httpx_target(hostname: str, http_info: dict, ports: list[int] | set[int] | tuple[int, ...]) -> str:
    url = str(http_info.get("url") or "").strip()
    if url:
        return url

    try:
        port_set = {int(port) for port in ports}
    except Exception:
        port_set = set()

    if 443 in port_set or 8443 in port_set:
        return f"https://{hostname}"
    if 80 in port_set or 8080 in port_set:
        return f"http://{hostname}"
    return ""


def probe_httpx_stack(target: str, debug: bool, timeout: int = 15) -> dict:
    result = {
        "checked": False,
        "status": "skipped",
        "source": "httpx",
        "target": target,
        "reason": "",
        "result": {},
    }

    if not target:
        result["reason"] = "No web endpoint available for httpx enrichment."
        return result

    httpx_path = HTTPX_STATE.get("path")
    if not httpx_path:
        result["reason"] = "httpx is not installed."
        return result

    if HTTPX_STATE.get("disabled_reason"):
        result["reason"] = HTTPX_STATE["disabled_reason"]
        return result

    cmd = [
        httpx_path,
        "-td",
        "-json",
        "-title",
        "-status-code",
        "-web-server",
        "-ip",
        "-cdn",
        "-asn",
        "-timeout",
        str(timeout),
        "-retries",
        "1",
        "-silent",
    ]
    log_dbg(f"Running httpx enrichment for {target}", debug)
    try:
        completed = subprocess.run(
            cmd,
            input=f"{target}\n",
            capture_output=True,
            text=True,
            timeout=timeout + 10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result["status"] = "error"
        result["reason"] = f"httpx timed out after {timeout + 10}s."
        return result
    except Exception as exc:
        HTTPX_STATE["disabled_reason"] = f"httpx execution failed: {exc}"
        result["reason"] = HTTPX_STATE["disabled_reason"]
        return result

    stdout = (completed.stdout or "").strip()
    stderr = (completed.stderr or "").strip()
    if completed.returncode != 0:
        HTTPX_STATE["disabled_reason"] = stderr or f"httpx exited with status {completed.returncode}."
        result["reason"] = HTTPX_STATE["disabled_reason"]
        return result

    payload = {}
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            break
        except json.JSONDecodeError:
            continue

    if not payload:
        result["status"] = "error"
        result["reason"] = stderr or "httpx returned no JSON result."
        return result

    result["checked"] = True
    result["status"] = "ok"
    result["reason"] = ""
    result["result"] = payload
    return result


def fetch_subdomains_subfinder(domain: str, debug: bool = False) -> list[str]:
    """Fetch hostnames using subfinder."""
    log_dbg(f"Running subfinder for {domain}...", debug)
    hosts = set()
    try:
        cmd = ["subfinder", "-d", domain, "-silent", "-all"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                host = normalize_domain(line.strip())
                if host and host.endswith(domain) and "*" not in host:
                    hosts.add(host)
            if hosts:
                log_dbg(f"Found {len(hosts)} unique hosts using subfinder", debug)
    except Exception as e:
        log_dbg(f"subfinder error: {e}", debug)
    return sorted(list(hosts))


def run_domain_shodan_checks(
    domain: str,
    provider_fragments: str,
    dns_page_limit: int = 4,
    host_enrichment_limit: int = 30,
    debug: bool = False,
) -> dict:
    target_domain = core_domain(normalize_domain(domain))
    log_dbg(f"Starting collection for {target_domain}", debug)

    env_key = os.environ.get("SHODANAPI", "").strip()
    file_key = load_shodan_key_file()
    api_key = env_key or file_key
    if not api_key:
        raise RuntimeError("No Shodan API key found")

    info_body, status = shodan_api_info(api_key, debug)
    shodan_info = json.loads(info_body) if status == 200 else {}

    hostname_sources = defaultdict(set)
    hostname_sources[target_domain].add("target")

    log_dbg(f"Discovering subdomains for {target_domain}...", debug)
    extra_hosts = fetch_subdomains_subfinder(target_domain, debug=debug)
    for host in extra_hosts:
        hostname_sources[host].add("subfinder")

    dns_records = []
    dns_tasks = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        for mode_label, history_flag in [("current", "false"), ("history", "true")]:
            for page in range(1, dns_page_limit + 1):
                url = f"https://api.shodan.io/dns/domain/{target_domain}?key={api_key}&history={history_flag}&page={page}"
                dns_tasks.append(executor.submit(shodan_get, url, debug, (mode_label, page)))

        for future in as_completed(dns_tasks):
            body, status, (mode_label, page) = future.result()
            if status != 200 or not body: continue
            try:
                data = json.loads(body)
            except: continue
            records = data.get("data", [])
            if not records and page > 1: continue
            for entry in records:
                sub = entry.get("subdomain") or ""
                fqdn = f"{sub}.{target_domain}" if sub else target_domain
                fqdn = fqdn.lower().rstrip(".")
                rec_type = entry.get("type", "UNKNOWN")
                value = str(entry.get("value") or "").rstrip(".")
                dns_records.append({
                    "hostname": fqdn, "type": rec_type, "value": value,
                    "last_seen": str(entry.get("last_seen") or ""),
                    "source": f"shodan_dns_{mode_label}"
                })
                hostname_sources[fqdn].add(f"shodan_dns_{mode_label}")
                val_norm = normalize_domain(value)
                if val_norm.endswith(target_domain):
                    hostname_sources[val_norm].add(f"shodan_dns_{mode_label}")
            for sub in data.get("subdomains", []):
                fqdn = f"{sub}.{target_domain}".lower().rstrip(".")
                hostname_sources[fqdn].add(f"shodan_dns_{mode_label}")

    unique_ips = set()
    for rec in dns_records:
        if rec["type"] in ("A", "AAAA"):
            unique_ips.add(rec["value"])
    
    enrichment_targets = sorted(list(unique_ips))[:host_enrichment_limit]
    ip_assets = []
    ip_summaries = {}
    with ThreadPoolExecutor(max_workers=8) as executor:
        host_tasks = []
        for ip in enrichment_targets:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}&minify=false"
            host_tasks.append(executor.submit(shodan_get, url, debug, ip))
        for future in as_completed(host_tasks):
            body, status, ip = future.result()
            if status == 200 and body:
                data = json.loads(body)
                ports = sorted(data.get("ports", []))
                
                # Extract detailed vulnerability information
                vulns_list = data.get("vulns", [])
                vuln_details = {}
                
                # Check data entries for vulnerability details (summary, cvss)
                for entry in data.get("data", []):
                    entry_vulns = entry.get("vulns", {})
                    if isinstance(entry_vulns, dict):
                        for cve_id, info in entry_vulns.items():
                            if cve_id not in vuln_details:
                                vuln_details[cve_id] = {
                                    "summary": info.get("summary", ""),
                                    "cvss": info.get("cvss", info.get("cvss_v3", info.get("cvss_v2", 0.0))),
                                    "verified": info.get("verified", False)
                                }
                
                # Ensure all CVEs in 'vulns' list have at least a placeholder entry in details
                for cve_id in vulns_list:
                    if cve_id not in vuln_details:
                        vuln_details[cve_id] = {"summary": "No details available.", "cvss": 0.0, "verified": False}

                # Capture HTTP titles and status from Shodan if present
                shodan_http_info = {}
                for entry in data.get("data", []):
                    if "http" in entry:
                        shodan_http_info[entry.get("port", 80)] = {
                            "status": entry["http"].get("status"),
                            "title": entry["http"].get("title"),
                        }

                ip_obj = {
                    "ip": ip, "ports": ports,
                    "products": sorted({entry.get("product") for entry in data.get("data", []) if entry.get("product")})[:10],
                    "vulns": sorted(list(vuln_details.keys())),
                    "vuln_details": vuln_details,
                    "org": data.get("org", ""), "isp": data.get("isp", ""),
                    "asn": data.get("asn", ""), "country": data.get("country_name", ""),
                    "city": data.get("city", "n/a"),
                    "domains": data.get("domains", []),
                    "hostnames": data.get("hostnames", []),
                    "os": data.get("os", ""),
                    "network_hint": f"{ip.rsplit('.', 1)[0]}.0/24" if ":" not in ip else f"{ip.rsplit(':', 1)[0]}:/64",
                    "shodan_http": shodan_http_info,
                }
                ip_assets.append(ip_obj)
                ip_summaries[ip] = ip_obj
                # Add all hostnames from Shodan to our tracking
                for h in data.get("hostnames", []):
                    h_norm = normalize_domain(h)
                    if h_norm.endswith(target_domain):
                        hostname_sources[h_norm].add("shodan_host")
                # Also add domains if relevant
                for d in data.get("domains", []):
                    d_norm = normalize_domain(d)
                    if d_norm.endswith(target_domain):
                        hostname_sources[d_norm].add("shodan_host")

    fragments = []
    if os.path.isfile(provider_fragments):
        with open(provider_fragments, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower().rstrip(".")
                if line: fragments.append(line)

    all_hostnames = sorted(hostname_sources.keys())
    http_results = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        probe_tasks = {executor.submit(probe_http_simple, h): h for h in all_hostnames[:150]}
        for future in as_completed(probe_tasks):
            h = probe_tasks[future]
            http_results[h] = future.result()

    host_profiles = []
    for host in all_hostnames:
        recs = [r for r in dns_records if r["hostname"] == host]
        current_ips = [r["value"] for r in recs if r["type"] in ("A", "AAAA")]
        cnames = [r["value"] for r in recs if r["type"] == "CNAME"]
        matches = []
        for cname in cnames:
            cname_norm = normalize_domain(cname)
            for frag in fragments:
                if cname_norm == frag or cname_norm.endswith(f".{frag}"):
                    matches.append({"target": cname_norm, "fragment": frag, "category": "Provider-linked"})
        http_info = http_results.get(host, {"probed": False, "reachable": False, "scheme": "", "url": "", "status_code": 0, "title": ""})
        
        # Fallback to Shodan HTTP info if active probe failed but Shodan has it
        if not http_info["reachable"]:
            for ip in current_ips:
                if ip in ip_summaries:
                    sh_http = ip_summaries[ip].get("shodan_http", {})
                    if sh_http:
                        # Pick first available web port (443, 80, etc)
                        for port in (443, 80, 8080, 8443):
                            if port in sh_http:
                                scheme = "https" if port in (443, 8443) else "http"
                                http_info = {
                                    "probed": True,
                                    "reachable": True,
                                    "scheme": scheme,
                                    "url": f"{scheme}://{host}",
                                    "status_code": sh_http[port].get("status", 200),
                                    "title": f"(Shodan) {sh_http[port].get('title', '')}"[:100]
                                }
                                break
                    if http_info["reachable"]: break
        score = 0
        factors = []
        host_vulns = set()
        host_vuln_details = {}
        host_ports = set()
        for ip in current_ips:
            if ip in ip_summaries:
                summ = ip_summaries[ip]
                if summ["ports"]:
                    score += min(15, len(summ["ports"]) * 2)
                    factors.append(f"Open ports on {ip}: {summ['ports']}")
                    host_ports.update(summ["ports"])
                if summ["vulns"]:
                    score += 25
                    factors.append(f"Vulnerabilities found on {ip}")
                    host_vulns.update(summ["vulns"])
                    host_vuln_details.update(summ.get("vuln_details", {}))
        if http_info["reachable"]:
            score += 15
            factors.append(f"Web service reachable ({http_info['status_code']})")
            if http_info["status_code"] == 200: score += 5
        if matches:
            score += 15
            factors.append(f"Provider-linked CNAME: {', '.join(m['target'] for m in matches)}")
            if not current_ips:
                score += 25
                factors.append("Dangling CNAME (Potential Takeover)")
        level = "low"
        if score >= 70: level = "critical"
        elif score >= 45: level = "high"
        elif score >= 25: level = "medium"
        
        # Aggregate Shodan metadata
        all_cities = set()
        all_domains = set()
        all_hostnames_from_shodan = set()
        for ip in current_ips:
            if ip in ip_summaries:
                s = ip_summaries[ip]
                if s.get("city") and s.get("city") != "n/a": all_cities.add(s["city"])
                all_domains.update(s.get("domains", []))
                all_hostnames_from_shodan.update(s.get("hostnames", []))

        httpx_target = choose_httpx_target(host, http_info, host_ports)
        web_intel = probe_httpx_stack(httpx_target, debug=debug, timeout=15)

        host_profiles.append({
            "hostname": host, "risk_score": score, "risk_level": level, "risk_factors": factors,
            "vulns": sorted(list(host_vulns)), "vuln_details": host_vuln_details,
            "ports": sorted(list(host_ports)),
            "current_ips": current_ips, "provider_matches": matches,
            "sources": sorted(list(hostname_sources[host])), "http": http_info,
            "web_intel": web_intel,
            "city": ", ".join(sorted(list(all_cities))) or "n/a",
            "shodan_domains": sorted(list(all_domains)),
            "shodan_hostnames": sorted(list(all_hostnames_from_shodan))
        })

    host_profiles.sort(key=lambda x: x["risk_score"], reverse=True)
    all_hosts = host_profiles
    top_hosts = all_hosts[:100]

    return {
        "target": {
            "input": domain, "core_domain": target_domain, "slug": target_domain.replace(".", "-"),
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "summary": {
            "host_count": len(top_hosts),
            "web_host_count": sum(1 for h in top_hosts if h["http"]["reachable"]),
            "ip_count": len(ip_assets),
            "critical_count": sum(1 for h in top_hosts if h["risk_level"] == "critical"),
            "high_count": sum(1 for h in top_hosts if h["risk_level"] == "high"),
            "medium_count": sum(1 for h in top_hosts if h["risk_level"] == "medium"),
            "low_count": sum(1 for h in top_hosts if h["risk_level"] == "low"),
            "original_total_hosts": len(all_hosts)
        },
        "discoveries": {
            "dns_records": dns_records[:100],
            "takeover_candidates": [h for h in all_hosts if h["provider_matches"] and not h["current_ips"]]
        },
        "hosts": top_hosts, "ips": ip_assets
    }


def main(argv) -> int:
    parser = build_parser()
    print_help_if_requested(parser, argv)
    args = parser.parse_args(argv)
    if not args.input_file or not args.fragments_file:
        log_err("Missing required input files.", args.debug)
        parser.print_help()
        return 1
    api_key = os.environ.get("SHODANAPI", "").strip() or load_shodan_key_file()
    if not api_key:
        log_err("No Shodan API key found.", args.debug)
        return 1
    suffixes = load_suffixes(args.fragments_file)
    scope_suffixes = SCOPE_SUFFIXES.get(args.scope) if args.scope else ()
    dedupe = set()
    print_header()
    out_handle, emit_output = init_output_writer(args)
    queried = set()
    try:
        for domain in read_lines(args.input_file):
            domain = normalize_domain(domain)
            if not domain: continue
            core = core_domain(domain)
            if core in queried: continue
            queried.add(core)
            url = f"https://api.shodan.io/dns/domain/{core}?key={api_key}&type=CNAME&page=1&history=false"
            body, status, _ = shodan_get(url, args.debug)
            if not body or status != 200: continue
            try:
                data = json.loads(body)
            except: continue
            records = data.get("data", [])
            for entry in records:
                if entry.get("type") != "CNAME": continue
                sub = entry.get("subdomain") or ""
                value = entry.get("value") or ""
                fqdn = f"{sub}.{core}" if sub else core
                if scope_suffixes:
                    if not is_suffix_match(extract_hostname(value), scope_suffixes): continue
                if not is_suffix_match(value, suffixes): continue
                key = f"{core}|{fqdn}|{value}"
                if key in dedupe: continue
                dedupe.add(key)
                item = {"domain": core, "subdomain": fqdn, "value": value}
                if emit_output: emit_output(item)
                print(f"{core:<30} {fqdn:<45} {value}")
    finally:
        if out_handle: out_handle.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
