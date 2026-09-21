from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

_LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
}

_IGNORED_DIR_NAMES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "vendor", "target",
}

_FRAMEWORK_SIGNATURES = {
    "flask": ("flask",),
    "fastapi": ("fastapi",),
    "django": ("django",),
    "express": ("express",),
    "nestjs": ("@nestjs/core",),
    "spring": ("spring-boot", "springframework"),
    "rails": ("rails",),
    "gin": ("gin-gonic",),
}

_MANIFEST_FILES = ("requirements.txt", "pyproject.toml", "Pipfile", "package.json", "go.mod", "Gemfile")


@dataclass(frozen=True)
class SourceFile:
    path: Path
    language: str


@dataclass(frozen=True)
class SourceIngestionResult:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    language_counts: dict[str, int] = field(default_factory=dict)
    primary_language: str | None = None
    frameworks: list[str] = field(default_factory=list)


def ingest_source(root: Path | str, max_files: int = 2000) -> SourceIngestionResult:
    """Walks a source tree collecting recognized source files and detecting
    the primary language + framework from manifest files. Bounded by
    max_files so a huge or misconfigured target can't make this run
    unbounded -- consistent with the project's Budget principle."""
    root_path = Path(root)
    files: list[SourceFile] = []
    language_counts: dict[str, int] = {}

    if root_path.is_dir():
        for path in sorted(root_path.rglob("*")):
            if len(files) >= max_files:
                break
            if not path.is_file():
                continue
            if any(part in _IGNORED_DIR_NAMES for part in path.relative_to(root_path).parts):
                continue
            language = _LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
            if language is None:
                continue
            files.append(SourceFile(path=path, language=language))
            language_counts[language] = language_counts.get(language, 0) + 1

    primary_language = max(language_counts, key=lambda lang: language_counts[lang]) if language_counts else None
    frameworks = _detect_frameworks(root_path)

    return SourceIngestionResult(
        root=root_path,
        files=files,
        language_counts=language_counts,
        primary_language=primary_language,
        frameworks=frameworks,
    )


def _detect_frameworks(root: Path) -> list[str]:
    detected: set[str] = set()
    for manifest_name in _MANIFEST_FILES:
        manifest_path = root / manifest_name
        if not manifest_path.is_file():
            continue
        try:
            text = manifest_path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError:
            continue
        for framework, signatures in _FRAMEWORK_SIGNATURES.items():
            if any(signature in text for signature in signatures):
                detected.add(framework)
    return sorted(detected)
