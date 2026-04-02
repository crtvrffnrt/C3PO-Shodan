#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import urllib.parse
from collections import defaultdict
from datetime import datetime, timezone


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
        "co.uk",
        "org.uk",
        "gov.uk",
        "ac.uk",
        "co.nz",
        "com.au",
        "net.au",
        "org.au",
        "co.jp",
        "com.br",
        "com.mx",
        "com.tr",
        "com.cn",
        "com.hk",
        "com.sg",
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
    return shodan_get(url, debug)


def shodan_get(url: str, debug: bool) -> tuple[str, int]:
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
            return ("", 0)

        if status == 200:
            log_dbg(f"Shodan response 200 for: {redact_url(url)}", debug)
            return (body, status)

        if status == 429 or "rate limit" in body.lower():
            log_dbg(f"Rate limited (status {status}); backing off {delay}s", debug)
            time.sleep(delay)
            delay *= 2
            continue

        log_dbg(f"Shodan API error ({status}): {redact_url(url)}", debug)
        return ("", status)

    log_dbg(f"Shodan API rate limit exceeded: {redact_url(url)}", debug)
    return ("", 429)


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


def run_domain_shodan_checks(
    domain: str,
    provider_fragments: str,
    dns_page_limit: int = 4,
    host_enrichment_limit: int = 30,
    debug: bool = False,
) -> dict:
    """
    Shodan-only replacement for collect-attack-surface.py.
    Provides a dictionary compatible with ReportPayload.
    """
    target_domain = core_domain(normalize_domain(domain))
    log_dbg(f"Starting Shodan-only collection for {target_domain}", debug)

    env_key = os.environ.get("SHODANAPI", "").strip()
    file_key = load_shodan_key_file()
    api_key = env_key or file_key
    if not api_key:
        raise RuntimeError("No Shodan API key found")

    # 1. API Info
    info_body, status = shodan_api_info(api_key, debug)
    shodan_info = json.loads(info_body) if status == 200 else {}

    # 2. DNS Collection (Current and History)
    dns_records = []
    hostname_sources = defaultdict(set)
    hostname_sources[target_domain].add("target")

    for mode_label, history_flag in [("current", "false"), ("history", "true")]:
        log_dbg(f"Fetching {mode_label} DNS records...", debug)
        url = f"https://api.shodan.io/dns/domain/{target_domain}?key={api_key}&history={history_flag}"
        body, status = shodan_get(url, debug)
        if status != 200 or not body:
            log_dbg(f"Failed to fetch {mode_label} DNS (status {status})", debug)
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            log_dbg(f"Invalid JSON for {mode_label} DNS", debug)
            continue

        records = data.get("data", [])
        log_dbg(f"Found {len(records)} {mode_label} DNS records", debug)

        for entry in records:
            sub = entry.get("subdomain") or ""
            fqdn = f"{sub}.{target_domain}" if sub else target_domain
            fqdn = fqdn.lower().rstrip(".")
            rec_type = entry.get("type", "UNKNOWN")
            value = str(entry.get("value") or "").rstrip(".")
            
            # Use a tuple as a key to avoid duplicates in dns_records
            dns_records.append({
                "hostname": fqdn,
                "type": rec_type,
                "value": value,
                "last_seen": str(entry.get("last_seen") or ""),
                "source": f"shodan_dns_{mode_label}"
            })
            hostname_sources[fqdn].add(f"shodan_dns_{mode_label}")
            
            # If value is a hostname in scope, track it
            val_norm = normalize_domain(value)
            if val_norm.endswith(target_domain):
                hostname_sources[val_norm].add(f"shodan_dns_{mode_label}")

    # 3. Host Enrichment
    unique_ips = set()
    for rec in dns_records:
        if rec["type"] in ("A", "AAAA"):
            unique_ips.add(rec["value"])
    
    log_dbg(f"Found {len(unique_ips)} unique IPs for enrichment", debug)
    enrichment_targets = sorted(list(unique_ips))[:host_enrichment_limit]
    log_dbg(f"Enriching top {len(enrichment_targets)} IPs", debug)
    ip_assets = []
    ip_summaries = {}

    for ip in enrichment_targets:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}&minify=false"
        body, status = shodan_get(url, debug)
        if status == 200 and body:
            data = json.loads(body)
            ports = sorted(data.get("ports", []))
            vulns = sorted(data.get("vulns", [])) if data.get("vulns") else []
            log_dbg(f"Enriched {ip}: {len(ports)} ports, {len(vulns)} vulns", debug)
            summary = {
                "ip": ip,
                "ports": ports,
                "products": sorted({entry.get("product") for entry in data.get("data", []) if entry.get("product")}),
                "vulns": vulns,
                "org": data.get("org", ""),
                "isp": data.get("isp", ""),
                "asn": data.get("asn", ""),
                "country": data.get("country_name", ""),
                "os": data.get("os", ""),
                "last_update": data.get("last_update", ""),
            }
            ip_assets.append(summary)
            ip_summaries[ip] = summary
            
            # Add discovered hostnames
            for h in data.get("hostnames", []):
                h_norm = normalize_domain(h)
                if h_norm.endswith(target_domain):
                    hostname_sources[h_norm].add("shodan_host")

    # 4. Suffix Analysis (Takeover)
    fragments = []
    if os.path.isfile(provider_fragments):
        with open(provider_fragments, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower().rstrip(".")
                if line:
                    fragments.append(line)

    host_profiles = []
    for host in sorted(hostname_sources.keys()):
        recs = [r for r in dns_records if r["hostname"] == host]
        current_ips = [r["value"] for r in recs if r["type"] in ("A", "AAAA")]
        cnames = [r["value"] for r in recs if r["type"] == "CNAME"]
        
        matches = []
        for cname in cnames:
            cname_norm = normalize_domain(cname)
            for frag in fragments:
                if cname_norm == frag or cname_norm.endswith(f".{frag}"):
                    matches.append({"target": cname_norm, "fragment": frag, "category": "Provider-linked"})
        
        # Risk Scoring (Simplified Shodan-only)
        score = 0
        factors = []
        host_vulns = set()
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
        
        if matches:
            score += 15
            factors.append(f"Provider-linked CNAME: {', '.join(m['target'] for m in matches)}")
            if not current_ips:
                score += 20
                factors.append("Dangling CNAME (no IP resolution)")

        level = "low"
        if score >= 60: level = "critical"
        elif score >= 40: level = "high"
        elif score >= 20: level = "medium"

        host_profiles.append({
            "hostname": host,
            "risk_score": score,
            "risk_level": level,
            "risk_factors": factors,
            "vulns": sorted(list(host_vulns)),
            "ports": sorted(list(host_ports)),
            "current_ips": current_ips,
            "provider_matches": matches,
            "sources": sorted(list(hostname_sources[host])),
            "http": {"probed": False, "reachable": False} # No active probes
        })

    host_profiles.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "target": {
            "input": domain,
            "core_domain": target_domain,
            "slug": target_domain.replace(".", "-"),
            "generated_at": datetime.now(timezone.utc).isoformat()
        },
        "summary": {
            "host_count": len(host_profiles),
            "ip_count": len(ip_assets),
            "critical_count": sum(1 for h in host_profiles if h["risk_level"] == "critical"),
            "high_count": sum(1 for h in host_profiles if h["risk_level"] == "high"),
            "medium_count": sum(1 for h in host_profiles if h["risk_level"] == "medium"),
            "low_count": sum(1 for h in host_profiles if h["risk_level"] == "low"),
        },
        "discoveries": {
            "dns_records": dns_records,
            "takeover_candidates": [h for h in host_profiles if h["provider_matches"]]
        },
        "hosts": host_profiles,
        "ips": ip_assets
    }


def main(argv) -> int:
    parser = build_parser()
    print_help_if_requested(parser, argv)
    args = parser.parse_args(argv)

    if not args.input_file or not args.fragments_file:
        log_err("Missing required input files.", args.debug)
        parser.print_help()
        return 1

    env_key = os.environ.get("SHODANAPI", "").strip()
    file_key = load_shodan_key_file()
    api_key = env_key or file_key
    fallback_key = file_key if env_key and file_key and env_key != file_key else ""
    if not api_key:
        log_err("No Shodan API key found in SHODANAPI or ~/.shodan/api_key.", args.debug)
        return 1
    info_body, info_status = shodan_api_info(api_key, args.debug)
    if info_status == 401 and fallback_key:
        log_dbg("401 with SHODANAPI; retrying api-info with ~/.shodan/api_key", args.debug)
        info_body, info_status = shodan_api_info(fallback_key, args.debug)
        if info_status == 200:
            api_key = fallback_key
    if info_status == 200 and info_body:
        try:
            info_data = json.loads(info_body)
            print(json.dumps(info_data, indent=2, sort_keys=True))
        except json.JSONDecodeError:
            log_err("Invalid JSON from Shodan api-info.", args.debug)
    else:
        log_err("Unable to fetch Shodan api-info; continuing.", args.debug)

    if not os.path.isfile(args.input_file):
        log_err(f"Cannot read input file: {args.input_file}", args.debug)
        return 1
    if not os.path.isfile(args.fragments_file):
        log_err(f"Cannot read fragments file: {args.fragments_file}", args.debug)
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
            if not domain:
                continue
            core = core_domain(domain)
            if core in queried:
                continue
            queried.add(core)
            
            url = f"https://api.shodan.io/dns/domain/{core}?key={api_key}&type=CNAME&page=1&history=false"
            body, status = shodan_get(url, args.debug)
            if not body or status != 200:
                continue
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                continue

            records = data.get("data", [])
            for entry in records:
                if entry.get("type") != "CNAME":
                    continue
                sub = entry.get("subdomain") or ""
                value = entry.get("value") or ""
                fqdn = f"{sub}.{core}" if sub else core

                if scope_suffixes:
                    host_for_scope = extract_hostname(value)
                    if not is_suffix_match(host_for_scope, scope_suffixes):
                        continue
                if not is_suffix_match(value, suffixes):
                    continue
                
                key = f"{core}|{fqdn}|{value}"
                if key in dedupe:
                    continue
                dedupe.add(key)
                
                item = {
                    "domain": core,
                    "subdomain": fqdn,
                    "value": value
                }
                if emit_output:
                    emit_output(item)
                print(f"{core:<30} {fqdn:<45} {value}")
    finally:
        if out_handle:
            out_handle.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
