import pytest

from core.profile import load_profile


def test_load_profile_reads_quick_profile() -> None:
    profile = load_profile("quick", "config/pipeline.yaml")
    assert profile.name == "quick"
    assert profile.testcase_limit == 5
    assert profile.judges == ["rule", "canary", "regex"]
    assert profile.executor.timeout_seconds == 10
    assert profile.executor.max_attempts == 1
    assert profile.reproduction_attempts == 1
    assert profile.reproduction_threshold == 1
    assert profile.mutation_enabled is False
    assert profile.targets == ["fake-llm"]
    assert profile.stages == ["scan"]


def test_load_profile_full_includes_all_stages_and_targets() -> None:
    profile = load_profile("full", "config/pipeline.yaml")
    assert profile.stages == ["recon", "scan", "adaptive", "external_scan"]
    assert profile.targets == ["fake-llm", "fake-agent", "fake-rag"]
    assert profile.mutation_enabled is True


def test_load_profile_web_has_no_scan_targets() -> None:
    profile = load_profile("web", "config/pipeline.yaml")
    assert profile.stages == ["recon", "external_scan"]
    assert profile.targets == []


def test_load_profile_raises_for_unknown_name() -> None:
    with pytest.raises(ValueError, match="unknown pipeline profile"):
        load_profile("does-not-exist", "config/pipeline.yaml")
