"""Fail closed on changed inputs and audit saved runs without executing them."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

from auto_forensics.cli import main
from auto_forensics.integrity import verify_run
from auto_forensics.manifest import hash_input_tree, read_run_manifest
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.plugins import PluginRegistry
from auto_forensics.replay import replay_manifest
from auto_forensics.security import SecurityError
from auto_forensics.version import __version__


def _run(tmp_path: Path, *, max_text_bytes: int = 4 * 1024 * 1024, rules: bool = False) -> tuple[Path, Path]:
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "sample.bin").write_bytes(b"MZ powershell synthetic fixture")
    (source / "notes.txt").write_text("a note longer than one byte", encoding="utf-8")
    rules_dir = None
    if rules:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.yaml").write_text("title: no match\ndetection:\n  keywords: [unlikely123]", encoding="utf-8")
    output = tmp_path / "output"
    run_case(PipelineConfig(
        "integrity-demo", source, output, llm_provider="mock",
        max_text_bytes=max_text_bytes, sigma_rules_dir=rules_dir,
    ))
    return source, output / "run_manifest.json"


def test_verify_is_read_only_and_reports_specific_input_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source, manifest = _run(tmp_path)
    before = {path.name: path.read_bytes() for path in manifest.parent.iterdir() if path.is_file()}
    monkeypatch.setattr("auto_forensics.replay.run_case", lambda *args: pytest.fail("verify must not execute a case"))
    assert verify_run(manifest)["match"] is True
    assert {path.name: path.read_bytes() for path in manifest.parent.iterdir() if path.is_file()} == before
    (source / "sample.bin").write_bytes(b"modified sample")
    (source / "notes.txt").unlink()
    (source / "added.txt").write_text("new", encoding="utf-8")
    result = verify_run(manifest)
    assert result["match"] is False
    assert result["input_changes"] == {"added": ["added.txt"], "missing": ["notes.txt"], "modified": ["sample.bin"]}
    assert result["report_match"] is True
    replay = replay_manifest(manifest)
    assert replay["match"] is False
    assert replay["executed"] is False
    assert not (manifest.parent / "replay").exists()


def test_verify_detects_report_tampering_and_supports_relocated_evidence(tmp_path: Path):
    source, manifest = _run(tmp_path)
    relocated = tmp_path / "copy"
    source.rename(relocated)
    assert verify_run(manifest)["match"] is False
    assert verify_run(manifest, input_dir=relocated)["match"] is True
    report_path = manifest.parent / "case_report.json"
    report = json.loads(report_path.read_text())
    report["summary"]["total_findings"] = 999
    report_path.write_text(json.dumps(report), encoding="utf-8")
    result = verify_run(manifest, input_dir=relocated)
    assert result["report_match"] is False
    assert result["match"] is False


def test_verify_hashes_other_formats_and_failed_render_preserves_previous_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source, manifest = _run(tmp_path)
    original = {path.name: path.read_bytes() for path in manifest.parent.iterdir()}

    def fail(*args):
        raise OSError("synthetic failure")

    monkeypatch.setattr("auto_forensics.pipeline._to_html", fail)
    with pytest.raises(OSError):
        run_case(PipelineConfig("integrity-demo", source, manifest.parent, llm_provider="mock"))
    assert {path.name: path.read_bytes() for path in manifest.parent.iterdir()} == original
    html = manifest.parent / "case_report.html"
    html.write_bytes(html.read_bytes() + b"modified")
    result = verify_run(manifest)
    assert result["report_match"] is True
    assert result["artifacts_match"] is False
    assert result["artifact_changes"] == ["case_report.html"]


def test_replay_repeats_parser_limits_and_checks_rule_hashes(tmp_path: Path):
    _source, manifest = _run(tmp_path, max_text_bytes=1, rules=True)
    recorded = read_run_manifest(manifest)
    assert recorded["manifest_version"] == 2
    assert recorded["config"]["max_text_bytes"] == 1
    assert recorded["resources"][0]["kind"] == "sigma_rules_dir"
    assert verify_run(manifest)["match"] is True
    assert replay_manifest(manifest)["match"] is True
    (tmp_path / "rules" / "example.yaml").write_text("title: changed", encoding="utf-8")
    assert verify_run(manifest)["resources_match"] is False
    result = replay_manifest(manifest, output_dir=tmp_path / "other-replay")
    assert result["resources_match"] is False
    assert result["executed"] is False


def test_replay_refuses_to_overwrite_source_outputs_or_evidence(tmp_path: Path):
    source, manifest = _run(tmp_path)
    before = manifest.read_bytes()
    for destination in (manifest.parent, source, source / "replay"):
        with pytest.raises(SecurityError, match="output|overwrite"):
            replay_manifest(manifest, output_dir=destination)
    assert manifest.read_bytes() == before


@pytest.mark.parametrize("mutation", [
    lambda m: m.update(manifest_version=True),
    lambda m: m.update(manifest_version=999),
    lambda m: m.update(input_files=[{}, {}]),
    lambda m: m["input_files"].append(copy.deepcopy(m["input_files"][0])),
    lambda m: m["input_files"][0].update(path="../outside.bin"),
    lambda m: m["input_files"][0].update(size_bytes=True),
    lambda m: m.update(output=[]),
    lambda m: m["output"].update(report="../outside.json"),
    lambda m: m["output"].update(report="different_report.json"),
    lambda m: m["model"].update(provider=[]),
    lambda m: m.update(input_dir="\x00"),
    lambda m: m["model"].update(endpoint=[]),
    lambda m: m["model"].update(seed=False),
    lambda m: m.update(paths={"unknown": "/tmp"}),
    lambda m: m.update(config={"max_text_bytes": "large"}),
    lambda m: m.update(resources=[{"kind": []}]),
])
def test_malformed_manifests_fail_before_replay(tmp_path: Path, mutation):
    _source, manifest = _run(tmp_path)
    raw = json.loads(manifest.read_text())
    mutation(raw)
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(SecurityError):
        replay_manifest(manifest)
    assert not (manifest.parent / "replay").exists()


def test_manifest_file_symlinks_cannot_redirect_verification_or_review(tmp_path: Path):
    _source, manifest = _run(tmp_path)
    real = tmp_path / "external_manifest.json"
    manifest.rename(real)
    manifest.symlink_to(real)
    for operation in (read_run_manifest, verify_run, replay_manifest):
        with pytest.raises(SecurityError, match="symlink"):
            operation(manifest)
    assert not (manifest.parent / "replay").exists()


def test_manifest_inventory_does_not_silently_truncate_or_omit_deep_files(tmp_path: Path):
    (tmp_path / "one.txt").write_text("one", encoding="utf-8")
    (tmp_path / "two.txt").write_text("two", encoding="utf-8")
    with pytest.raises(SecurityError, match="file limit"):
        hash_input_tree(tmp_path, max_files=1)
    deep = tmp_path.joinpath(*["sub"] * 20)
    deep.mkdir(parents=True)
    (deep / "deep.txt").write_text("deep", encoding="utf-8")
    with pytest.raises(SecurityError, match="depth"):
        hash_input_tree(tmp_path)


def test_tree_traversal_is_bounded_even_when_directories_and_links_have_no_regular_files(tmp_path: Path):
    from auto_forensics.security import bounded_tree_paths

    for index in range(6):
        (tmp_path / f"empty-{index}").mkdir()
    with pytest.raises(SecurityError, match="entry limit"):
        list(bounded_tree_paths(tmp_path, max_entries=5))
    outside = tmp_path.parent / "outside-tree"
    outside.mkdir(exist_ok=True)
    (outside / "not-traversed.txt").write_text("outside")
    (tmp_path / "linked-dir").symlink_to(outside, target_is_directory=True)
    paths = list(bounded_tree_paths(tmp_path))
    assert tmp_path / "linked-dir" in paths
    assert not any(path.name == "not-traversed.txt" for path in paths)


def test_changed_evidence_during_analysis_is_not_published(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "evidence"
    source.mkdir()
    (source / "sample.bin").write_bytes(b"MZ powershell")
    analyze = PluginRegistry.analyze_binary

    def change_after_analysis(registry: PluginRegistry, path: Path):
        feature = analyze(registry, path)
        path.write_bytes(b"different evidence")
        return feature

    monkeypatch.setattr(PluginRegistry, "analyze_binary", change_after_analysis)
    output = tmp_path / "output"
    with pytest.raises(SecurityError, match="changed during analysis"):
        run_case(PipelineConfig("changing-case", source, output, llm_provider="mock"))
    assert not output.exists()


def test_verify_cli_and_version(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    _source, manifest = _run(tmp_path)
    monkeypatch.setattr(sys, "argv", ["auto-forensics", "verify", str(manifest)])
    main()
    assert json.loads(capsys.readouterr().out)["match"] is True
    monkeypatch.setattr(sys, "argv", ["auto-forensics", "--version"])
    with pytest.raises(SystemExit) as result:
        main()
    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == __version__


def test_v1_manifests_remain_readable_with_explicit_resource_warning(tmp_path: Path):
    _source, manifest = _run(tmp_path)
    raw = json.loads(manifest.read_text())
    raw["manifest_version"] = 1
    raw.pop("resources")
    raw.pop("config")
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    result = verify_run(manifest)
    assert result["match"] is True
    assert result["warnings"]
    assert replay_manifest(manifest)["match"] is True


@pytest.mark.parametrize("version", ["0.1.0", "future-version", None])
def test_other_tool_versions_can_be_verified_but_cannot_be_replayed_or_reviewed(tmp_path: Path, monkeypatch, version):
    from auto_forensics.reviews import ReviewError, record_review

    _source, manifest = _run(tmp_path)
    raw = json.loads(manifest.read_text())
    if version is None:
        raw.pop("tool_version")
    else:
        raw["tool_version"] = version
    manifest.write_text(json.dumps(raw))
    verification = verify_run(manifest)
    assert verification["match"] is True and verification["warnings"]
    before = {path.name: path.read_bytes() for path in manifest.parent.iterdir()}
    monkeypatch.setattr("auto_forensics.replay.run_case", lambda *args, **kwargs: pytest.fail("Version mismatch must not execute analysis"))
    replay = replay_manifest(manifest)
    assert replay["executed"] is False and replay["tool_version_match"] is False
    assert replay["version_error"]
    finding_id = json.loads((manifest.parent / "case_report.json").read_text())["findings"][0]["finding_id"]
    with pytest.raises(ReviewError, match="tool version"):
        record_review(manifest.parent, finding_id=finding_id, decision="accept", actor="Ada")
    assert before == {path.name: path.read_bytes() for path in manifest.parent.iterdir()}


def test_yara_includes_are_confined_to_the_recorded_rule_tree(tmp_path: Path):
    pytest.importorskip("yara")
    from auto_forensics.yara_detector import _compile_rules

    root = tmp_path / "rules"
    root.mkdir()
    (root / "helpers.inc").write_text("private rule helper { condition: true }", encoding="utf-8")
    rule = root / "example.yar"
    rule.write_text('include "helpers.inc"\nrule example { condition: helper }', encoding="utf-8")
    assert len(_compile_rules(root)) == 1
    outside = tmp_path / "outside.inc"
    outside.write_text("private rule outside { condition: true }", encoding="utf-8")
    rule.write_text('include "../outside.inc"\nrule example { condition: outside }', encoding="utf-8")
    assert _compile_rules(root) == []
