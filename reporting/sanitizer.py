from __future__ import annotations

import re
from pathlib import Path


PATTERNS = [
    (re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9._-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie:\s*)[^\n]+"), r"\1[REDACTED]"),
    (re.compile(r"CANARY-SECRET-[0-9]+"), "CANARY-[REDACTED]"),
]


def sanitize_text(text: str) -> str:
    sanitized = text
    for pattern, replacement in PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_artifact(input_path: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / input_path.name
    output_path.write_text(sanitize_text(input_path.read_text(encoding="utf-8")), encoding="utf-8")
    log_path = output_dir / f"{input_path.stem}.redaction.log"
    log_path.write_text(f"source={input_path}\noutput={output_path}\n", encoding="utf-8")
    return output_path

