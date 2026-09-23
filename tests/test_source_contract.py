"""P4.2-A SourceFact/LanguageSourceAnalyzer contract (roadmap v4.2.0
Source Intelligence Expansion): a per-language dispatch registry that
replaces source/analyzers.py's hardcoded "if python do X, else no-op"
per signal type.
"""

from pathlib import Path

from source.analyzers import analyze_files
from source.contract import LanguageSourceAnalyzer, get_language_analyzer, register_language_analyzer, registered_languages
from source.ingestion import SourceFile
from source.models import DataEdge


def test_python_is_registered_by_default() -> None:
    assert "python" in registered_languages()
    analyzer = get_language_analyzer("python")
    assert analyzer is not None
    assert analyzer.trace_dataflow is not None
    assert analyzer.find_auth_guards is not None


def test_unregistered_language_returns_none() -> None:
    assert get_language_analyzer("cobol") is None


def test_registering_a_new_language_makes_it_reachable_through_the_registry() -> None:
    def fake_trace_dataflow(path: Path, text: str) -> list[DataEdge]:
        return [DataEdge(source="request", sink="fake_sink", file=str(path), line=1)]

    register_language_analyzer(LanguageSourceAnalyzer(language="fakelang", trace_dataflow=fake_trace_dataflow))

    analyzer = get_language_analyzer("fakelang")
    assert analyzer is not None
    edges = analyzer.trace_dataflow(Path("app.fake"), "irrelevant text")
    assert edges[0].sink == "fake_sink"


def test_analyze_files_uses_the_registry_for_dataflow_and_auth(tmp_path: Path) -> None:
    # A registered analyzer for an otherwise-unknown language is picked
    # up by analyzers.py's dispatch without any change to analyzers.py
    # itself -- the whole point of the P4.2-A contract.
    def fake_trace_dataflow(path: Path, text: str) -> list[DataEdge]:
        return [DataEdge(source="request", sink="fake_sink", file=str(path), line=3)]

    register_language_analyzer(LanguageSourceAnalyzer(language="madeup", trace_dataflow=fake_trace_dataflow))

    source_path = tmp_path / "handler.madeup"
    source_path.write_text("irrelevant text", encoding="utf-8")
    source_file = SourceFile(path=source_path, language="madeup")

    items = analyze_files([source_file])
    dataflow_items = [item for item in items if item.asset_type == "dataflow"]
    assert dataflow_items
    assert dataflow_items[0].metadata["sink_type"] == "fake_sink"


def test_analyze_files_produces_no_dataflow_items_for_a_language_with_no_registered_analyzer(tmp_path: Path) -> None:
    source_path = tmp_path / "unknown.zzz"
    source_path.write_text("whatever", encoding="utf-8")
    source_file = SourceFile(path=source_path, language="totally-unregistered-language")

    items = analyze_files([source_file])
    assert [item for item in items if item.asset_type == "dataflow"] == []
