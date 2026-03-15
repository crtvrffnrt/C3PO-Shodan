#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slugify(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    return cleaned or "host"


def debug_log(message: str, enabled: bool) -> None:
    if enabled:
        print(message, file=sys.stderr)


def detect_tool() -> tuple[str, str]:
    chromium_candidates = [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "microsoft-edge",
    ]
    for candidate in chromium_candidates:
        path = shutil.which(candidate)
        if path:
            return "chromium", path
    wkhtmltoimage = shutil.which("wkhtmltoimage")
    if wkhtmltoimage:
        return "wkhtmltoimage", wkhtmltoimage
    return "", ""


def chromium_commands(binary: str, url: str, output_path: str, width: int, height: int) -> list[list[str]]:
    return [
        [
            binary,
            "--headless=new",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-sandbox",
            f"--window-size={width},{height}",
            "--virtual-time-budget=12000",
            f"--screenshot={output_path}",
            url,
        ],
        [
            binary,
            "--headless",
            "--disable-gpu",
            "--hide-scrollbars",
            "--no-sandbox",
            f"--window-size={width},{height}",
            "--virtual-time-budget=12000",
            f"--screenshot={output_path}",
            url,
        ],
    ]


def capture_with_chromium(binary: str, url: str, output_path: str, width: int, height: int, timeout: int, debug: bool) -> tuple[bool, str]:
    for command in chromium_commands(binary, url, output_path, width, height):
        debug_log(f"[debug] Screenshot command: {' '.join(command[:-1])} <url>", debug)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except Exception as exc:
            return False, str(exc)
        if result.returncode == 0 and os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
            return True, ""
    return False, "Chromium-based screenshot command failed"


def capture_with_wkhtmltoimage(binary: str, url: str, output_path: str, width: int, height: int, timeout: int) -> tuple[bool, str]:
    command = [
        binary,
        "--width",
        str(width),
        "--height",
        str(height),
        url,
        output_path,
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception as exc:
        return False, str(exc)
    if result.returncode == 0 and os.path.isfile(output_path) and os.path.getsize(output_path) > 0:
        return True, ""
    return False, "wkhtmltoimage failed"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Capture screenshots for reachable web hosts in the raw attack-surface JSON.")
    parser.add_argument("--input", required=True, help="Raw JSON file from collect-attack-surface.py")
    parser.add_argument("--output", required=True, help="Screenshot manifest JSON path")
    parser.add_argument("--screenshot-dir", required=True, help="Directory for PNG output")
    parser.add_argument("--max-screenshots", type=int, default=16, help="Maximum screenshots to capture")
    parser.add_argument("--timeout", type=int, default=35, help="Per-host screenshot timeout")
    parser.add_argument("--width", type=int, default=1440, help="Screenshot width")
    parser.add_argument("--height", type=int, default=1024, help="Screenshot height")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser


def main(argv: list[str]) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    with open(args.input, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    os.makedirs(args.screenshot_dir, exist_ok=True)
    tool_type, tool_path = detect_tool()

    hosts = payload.get("hosts") or []
    candidates = []
    for host in hosts:
        http = host.get("http") or {}
        if http.get("reachable") and http.get("url"):
            candidates.append(
                {
                    "hostname": host.get("hostname", ""),
                    "url": http.get("url", ""),
                    "risk_score": int(host.get("risk_score", 0)),
                }
            )

    candidates.sort(key=lambda item: (-item["risk_score"], item["hostname"]))
    entries = []

    if not tool_path:
        for item in candidates[: args.max_screenshots]:
            entries.append(
                {
                    "hostname": item["hostname"],
                    "url": item["url"],
                    "status": "skipped",
                    "reason": "No supported screenshot tool found",
                    "path": "",
                }
            )
        manifest = {
            "generated_at": now_iso(),
            "tool": "",
            "entries": entries,
        }
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2)
            handle.write("\n")
        return 0

    for item in candidates[: args.max_screenshots]:
        filename = f"{slugify(item['hostname'])}.png"
        output_path = os.path.join(args.screenshot_dir, filename)
        if os.path.exists(output_path):
            os.remove(output_path)

        if tool_type == "chromium":
            ok, error = capture_with_chromium(
                tool_path,
                item["url"],
                output_path,
                args.width,
                args.height,
                args.timeout,
                args.debug,
            )
        else:
            ok, error = capture_with_wkhtmltoimage(
                tool_path,
                item["url"],
                output_path,
                args.width,
                args.height,
                args.timeout,
            )

        entries.append(
            {
                "hostname": item["hostname"],
                "url": item["url"],
                "status": "captured" if ok else "failed",
                "reason": "" if ok else error,
                "path": output_path if ok else "",
            }
        )

    manifest = {
        "generated_at": now_iso(),
        "tool": tool_path,
        "entries": entries,
    }
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
