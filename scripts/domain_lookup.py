#!/usr/bin/env python3
import argparse
import json
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

UUID_RE = re.compile(r"/([0-9a-fA-F-]{36})/oauth2/")

def get_json(url: str) -> dict:
    req = Request(url, headers={"User-Agent": "tenant-domain-lookup/1.0"})
    with urlopen(req, timeout=15) as resp:
        return json.load(resp)

def resolve_tenant_id(domain: str) -> str:
    try:
        cfg = get_json(
            f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
        )
        token_endpoint = cfg.get("token_endpoint", "")
        match = UUID_RE.search(token_endpoint)
        if not match:
            return ""
        return match.group(1)
    except:
        return ""

def lookup_known_domains(tenant_id: str) -> list[str]:
    if not tenant_id:
        return []
    try:
        data = get_json(
            f"https://tenant-api.micahvandeusen.com/search?tenant_id={tenant_id}"
        )
        domains = data.get("domains")
        if not isinstance(domains, list):
            return []
        return sorted(set(str(d).strip().lower() for d in domains if str(d).strip()))
    except:
        return []

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resolve related domains via Microsoft tenant ID."
    )
    parser.add_argument("domain", help="Seed domain")
    parser.add_argument("--max", type=int, default=10, help="Max domains to return")
    args = parser.parse_args()

    domain = args.domain.lower().strip()
    tenant_id = resolve_tenant_id(domain)
    if not tenant_id:
        # Fallback: just return the input domain if no tenant found
        print(domain)
        return 0

    related = lookup_known_domains(tenant_id)
    # Filter and ensure the original is included
    all_domains = set([domain])
    for d in related:
        if d:
            all_domains.add(d)
    
    # Sort and take max 10
    result = sorted(list(all_domains))[:args.max]
    for d in result:
        print(d)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
