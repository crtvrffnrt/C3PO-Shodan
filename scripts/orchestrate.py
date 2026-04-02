#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.orchestrator import run_pipeline


def load_yaml(path: str) -> dict:
    data = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            key, value = line.split(":", 1)
            data[key.strip()] = value.strip().strip('"').strip("'")
    return data


def build_parser():
    p = argparse.ArgumentParser()
    p.add_argument("domains", nargs=1)
    p.add_argument("--output-dir", default="output")
    p.add_argument("--html-output")
    p.add_argument("--json-output")
    p.add_argument("--model", default="gemini-2.0-flash")
    p.add_argument("--related-domain", action="append", dest="related_domains", default=[])
    p.add_argument("--debug", action="store_true")
    return p


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    project_root = ROOT
    config = load_yaml(str(project_root / "config" / "config.yaml"))
    payload = run_pipeline(
        domains=args.domains,
        related_domains=args.related_domains,
        config=config,
        provider_fragments_path=str(project_root / "config" / "provider-fragments.txt"),
        docs_index_ref=str(project_root / "docs" / "index-ref.html"),
        output_dir=args.output_dir,
        model=args.model,
        debug=args.debug,
    )
    os.makedirs(args.output_dir, exist_ok=True)
    html_path = args.html_output or str(Path(args.output_dir) / "report.html")
    json_path = args.json_output or str(Path(args.output_dir) / "report.json")
    with open(html_path, "w", encoding="utf-8") as handle:
        handle.write(payload["html"])
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    print(html_path)
    print(json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
