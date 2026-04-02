#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pipeline.gemini_client import run_gemini



def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--model", default="")
    args = p.parse_args(argv)
    with open(args.input, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    
    # Minimal payload for prompt to save tokens
    summary_data = {
        "target": payload.get("target"),
        "summary": payload.get("summary"),
        "top_hosts": [
            {"h": h.get("hostname"), "l": h.get("risk_level"), "f": h.get("risk_factors"), "v": h.get("vulns")}
            for h in payload.get("hosts", [])[:5]
        ],
        "txt": payload.get("discoveries", {}).get("interesting_txt", [])[:10]
    }

    prompt = (
        "Act as a Senior EASM Specialist. Generate a concise CISO Executive Report (2-3 min read) based on the payload.\n"
        "FORMAT:\n"
        "1. HEADLINE: Business Impact (Statement on operational/reputational risk).\n"
        "2. TOP 5 RISKS: Prioritized. Include '~all' SPF softfail if present (flag as 'Risky SPF Softfail').\n"
        "3. RECOMMENDATIONS: Actionable steps. For CVEs, recommend a Pentest to validate business impact.\n"
        "4. COMPANY-PERSPECTIVE CRITICALITY: Define for each major risk.\n"
        "LANGUAGE: German. Tone: Professional and urgent. No fluff.\n\n"
        f"DATA:\n{json.dumps(summary_data, indent=2, ensure_ascii=False)}"
    )
    result = run_gemini(prompt, model=args.model)
    print(result.text or result.raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
