from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass

FLASH_MODEL = "gemini-3-flash-preview"
DEFAULT_TIMEOUT_SECONDS = 380


@dataclass
class GeminiResult:
    text: str
    raw: str
    ok: bool


def _resolve_timeout(timeout_seconds: int | None) -> int:
    if timeout_seconds is not None:
        return max(1, int(timeout_seconds))
    raw = os.environ.get("C3PO_GEMINI_TIMEOUT_SECONDS") or os.environ.get("GEMINI_TIMEOUT_SECONDS") or ""
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS


def run_gemini(prompt: str, model: str = "", debug: bool = False, timeout_seconds: int | None = None) -> GeminiResult:
    if not shutil.which("gemini"):
        return GeminiResult(text="", raw="gemini CLI not found in PATH", ok=False)

    timeout_seconds = _resolve_timeout(timeout_seconds)
    cmd = ["gemini"]
    if model:
        cmd.extend(["-m", model])
    cmd.extend(["-p", prompt, "-o", "text"])
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return GeminiResult(
            text="",
            raw=f"gemini CLI timed out after {timeout_seconds}s",
            ok=False,
        )
    except Exception as exc:
        return GeminiResult(text="", raw=str(exc), ok=False)
    raw = (result.stdout or "") + (result.stderr or "")
    return GeminiResult(text=result.stdout.strip(), raw=raw.strip(), ok=result.returncode == 0 and bool(result.stdout.strip()))


def render_json_prompt(title: str, payload: dict, instruction: str) -> str:
    return (
        f"{instruction}\n\n"
        f"Return only JSON.\n"
        f"Context title: {title}\n"
        f"Payload:\n{json.dumps(payload, indent=2, ensure_ascii=False)}"
    )
