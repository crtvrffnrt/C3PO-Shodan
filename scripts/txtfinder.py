#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Enrich TXT DNS findings from a collected attack-surface JSON file.")
    p.add_argument("--input", required=True, help="Input attack-surface JSON.")
    p.add_argument("--output", required=True, help="Output TXT findings JSON.")
    return p


def normalize_value(value: str) -> str:
    return " ".join(str(value).split()).strip()


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    with open(args.input, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    discoveries = payload.get("discoveries", {})
    hosts = payload.get("hosts", [])

    dedup = {}
    for item in discoveries.get("interesting_txt", []):
        key = (item.get("hostname", ""), item.get("label", ""), normalize_value(item.get("value", "")))
        dedup[key] = {
            "hostname": item.get("hostname", ""),
            "label": item.get("label", ""),
            "value": normalize_value(item.get("value", "")),
            "source": item.get("source", ""),
        }

    for host in hosts:
        hostname = host.get("hostname", "")
        for txt in host.get("txt_records", []) or []:
            txt_value = normalize_value(txt)
            if not txt_value:
                continue
            key = (hostname, "TXT record", txt_value)
            dedup.setdefault(
                key,
                {
                    "hostname": hostname,
                    "label": "TXT record",
                    "value": txt_value,
                    "source": "txt_records",
                },
            )

    by_host = defaultdict(list)
    for item in dedup.values():
        by_host[item["hostname"]].append(item)

    for items in by_host.values():
        items.sort(key=lambda entry: (entry["label"], entry["value"]))

    output = {
        "generated_at": payload.get("target", {}).get("generated_at", ""),
        "entries": [item for host_items in sorted(by_host.values(), key=lambda items: items[0]["hostname"] if items else "") for item in host_items],
    }

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
