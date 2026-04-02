from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

FLASH_MODEL = "gemini-2.0-flash-exp"


@dataclass
class GeminiResult:
    text: str
    raw: str
    ok: bool


def run_gemini(prompt: str, model: str = "", debug: bool = False) -> GeminiResult:
    cmd = ["gemini"]
    if model:
        cmd.extend(["-m", model])
    cmd.extend(["-p", prompt, "-o", "text"])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
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
