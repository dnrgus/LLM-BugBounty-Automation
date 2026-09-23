"""P4.4-A Ground Truth Schema (roadmap v4.4.0 Accuracy & Benchmark)."""

from pathlib import Path

from attack_surface.models import AttackSurfaceItem
from benchmarks.ground_truth import GroundTruthFinding, load_ground_truth, load_ground_truth_corpus


def test_matches_on_asset_type_file_line_and_sink_type() -> None:
    truth = GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", line=10, sink_type="os_command")
    item = AttackSurfaceItem(
        source_type="source", asset_type="dataflow", location="app.py:10",
        metadata={"file": "app.py", "line": 10, "sink_type": "os_command"},
    )
    assert truth.matches(item) is True


def test_does_not_match_wrong_asset_type() -> None:
    truth = GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py")
    item = AttackSurfaceItem(source_type="source", asset_type="secret", location="app.py:10", metadata={"file": "app.py"})
    assert truth.matches(item) is False


def test_does_not_match_wrong_sink_type() -> None:
    truth = GroundTruthFinding(id="t1", asset_type="dataflow", file="app.py", sink_type="os_command")
    item = AttackSurfaceItem(
        source_type="source", asset_type="dataflow", location="app.py:10",
        metadata={"file": "app.py", "sink_type": "sql_injection"},
    )
    assert truth.matches(item) is False


def test_line_is_optional_and_skipped_when_not_given() -> None:
    truth = GroundTruthFinding(id="t1", asset_type="secret", file="app.py", secret_type="aws_access_key")
    item = AttackSurfaceItem(
        source_type="source", asset_type="secret", location="app.py:99",
        metadata={"file": "app.py", "line": 99, "secret_type": "aws_access_key"},
    )
    assert truth.matches(item) is True


def test_load_ground_truth_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "fixture.ground_truth.yaml"
    path.write_text(
        "fixture_path: some/fixture\n"
        "findings:\n"
        "  - id: f1\n"
        "    asset_type: dataflow\n"
        "    file: some/fixture/app.py\n"
        "    sink_type: os_command\n",
        encoding="utf-8",
    )
    entry = load_ground_truth(path)
    assert entry.fixture_path == "some/fixture"
    assert len(entry.findings) == 1
    assert entry.findings[0].id == "f1"


def test_load_ground_truth_corpus_finds_all_yaml_files_non_recursive(tmp_path: Path) -> None:
    (tmp_path / "a.ground_truth.yaml").write_text("fixture_path: a\nfindings: []\n", encoding="utf-8")
    (tmp_path / "b.ground_truth.yaml").write_text("fixture_path: b\nfindings: []\n", encoding="utf-8")
    (tmp_path / "not_relevant.yaml").write_text("fixture_path: c\nfindings: []\n", encoding="utf-8")

    corpus = load_ground_truth_corpus(tmp_path)
    assert {entry.fixture_path for entry in corpus} == {"a", "b"}


def test_load_ground_truth_corpus_missing_dir_returns_empty() -> None:
    assert load_ground_truth_corpus("does/not/exist") == []


def test_real_sample_app_corpus_entry_loads() -> None:
    entry = load_ground_truth("benchmarks/corpus/sample_app.ground_truth.yaml")
    assert entry.fixture_path == "tests/fixtures/source/sample_app"
    assert len(entry.findings) == 4
