from __future__ import annotations

from pathlib import Path

import yaml

from testcase.schema import Testcase


def load_testcases(path: Path | str) -> list[Testcase]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    items = data.get("testcases", data if isinstance(data, list) else [])
    return [Testcase(**item) for item in items]

