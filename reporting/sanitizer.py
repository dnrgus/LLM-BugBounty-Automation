from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Redaction:
    name: str
    count: int


@dataclass(frozen=True)
class SanitizedArtifact:
    path: Path
    log_path: Path
    redactions: list[Redaction]


PATTERNS = [
    ("authorization_bearer", re.compile(r"(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._-]+"), r"\1[REDACTED]"),
    ("api_key", re.compile(r"(?i)(api[_-]?key['\"]?\s*[:=]\s*['\"]?)[A-Za-z0-9._-]+"), r"\1[REDACTED]"),
    ("cookie", re.compile(r"(?i)(cookie:\s*)[^\n]+"), r"\1[REDACTED]"),
    ("canary", re.compile(r"CANARY-SECRET-[0-9]+"), "CANARY-[REDACTED]"),
    ("email", re.compile(r"(?i)[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}"), "[EMAIL-REDACTED]"),
]


def sanitize_text(text: str) -> tuple[str, list[Redaction]]:
    sanitized = text
    redactions: list[Redaction] = []
    for name, pattern, replacement in PATTERNS:
        sanitized, count = pattern.subn(replacement, sanitized)
        if count:
            redactions.append(Redaction(name=name, count=count))
    return sanitized, redactions


def sanitize_artifact(input_path: Path, output_dir: Path) -> SanitizedArtifact:
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / input_path.name
    sanitized, redactions = sanitize_text(input_path.read_text(encoding="utf-8"))
    output_path.write_text(sanitized, encoding="utf-8")
    log_path = output_dir / f"{input_path.stem}.redaction.log"
    log_lines = [
        f"source={input_path}",
        f"output={output_path}",
        "redactions:",
    ]
    log_lines.extend(f"- {item.name}: {item.count}" for item in redactions)
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    return SanitizedArtifact(path=output_path, log_path=log_path, redactions=redactions)
