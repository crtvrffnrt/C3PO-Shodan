#!/usr/bin/env python3
import argparse
import json
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
domain = "bechtle.de"
UUID_RE = re.compile(r"/([0-9a-fA-F-]{36})/oauth2/")

def get_json(url: str) -> dict:
    req = Request(url, headers={"User-Agent": "tenant-domain-lookup/1.0"})
    with urlopen(req, timeout=15) as resp:
        return json.load(resp)

def resolve_tenant_id(domain: str) -> str:
    cfg = get_json(
        f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    )
    token_endpoint = cfg.get("token_endpoint", "")
    match = UUID_RE.search(token_endpoint)
    if not match:
        raise ValueError(f"Could not extract tenant ID from token_endpoint for {domain}")
    return match.group(1)

def lookup_known_domains(tenant_id: str) -> list[str]:
    data = get_json(
        f"https://tenant-api.micahvandeusen.com/search?tenant_id={tenant_id}"
    )
    domains = data.get("domains")
    if not isinstance(domains, list):
        raise ValueError("Correlation API did not return a domains list")
    return sorted(set(str(d).strip() for d in domains if str(d).strip()))

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve a Microsoft tenant ID from a domain and return known related domains."
    )
    parser.add_argument("domain", help="Seed domain, e.g. bechtle.de")
    args = parser.parse_args()

    try:
        tenant_id = resolve_tenant_id(args.domain)
        domains = lookup_known_domains(tenant_id)
    except HTTPError as e:
        print(f"[!] HTTP error: {e.code} {e.reason}", file=sys.stderr)
        return 2
    except URLError as e:
        print(f"[!] Network error: {e.reason}", file=sys.stderr)
        return 3
    except Exception as e:
        print(f"[!] Lookup failed: {e}", file=sys.stderr)
        return 4

    print(f"tenant_id={tenant_id}")
    for domain in domains:
        print(domain)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
