"""Disk images: artefacts are copied out read-only, within budget, with safe names, and cited by image path."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import pytest

from auto_forensics.security import SecurityError
from auto_forensics_autopilot import agents as agents_module
from auto_forensics_autopilot import disk_images
from auto_forensics_autopilot.disk_images import (
    DiskBudget,
    disk_support,
    group_images,
    open_image,
    read_image,
    safe_component,
)
from auto_forensics_autopilot.orchestrator import DRAFT_JSON, DRAFT_MD, start
from auto_forensics_autopilot.triage import classify, plan_agents, profile_evidence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _fat_image import build_fat_image  # noqa: E402

CANARY = "CANARY-d15k-77"
HISTORY = "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"


def _windows_tree(**extra_tasks: bytes) -> dict:
    tasks = {"Updater": b"<?xml version='1.0'?><Task/>", **extra_tasks}
    return {
        "Windows": {
            "System32": {
                "winevt": {"Logs": {"Application.evtx": b"ElfFile\x00" + b"\0" * 120}},
                "config": {"SYSTEM": b"regf" + b"\0" * 60},
                "Tasks": tasks,
            },
            "Prefetch": {"CALC.EXE-12345678.pf": b"MAM\x04" + b"\0" * 40},
            "inf": {"setupapi.dev.log": b">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_Test]\n"},
        },
        "Users": {
            "alice": {
                "NTUSER.DAT": b"regf" + b"\0" * 20,
                "Documents": {"private-letter.txt": f"not an artefact {CANARY}\n".encode()},
                "AppData": {"Roaming": {"Microsoft": {"Windows": {
                    "Recent": {"report.lnk": b"L\0\0\0" + b"\0" * 16},
                    "PowerShell": {"PSReadLine": {"ConsoleHost_history.txt":
                                                  b"whoami\nmimikatz sekurlsa::logonpasswords\n"}},
                }}}},
            },
        },
        "$Recycle.Bin": {"S-1-5-21-1001": {"$IABC123.docx": b"\x02" + b"\0" * 20, "$RABC123.docx": b"content"}},
    }


def _needs_dissect() -> None:
    pytest.importorskip("dissect.target")
    pytest.importorskip("dissect.fat")


# --------------------------------------------------------------------------
# Without dissect: grouping, triage, names, budgets, missing extra
# --------------------------------------------------------------------------


def test_segments_are_grouped_under_the_file_dissect_opens() -> None:
    groups, orphans = group_images([
        "pc/pc.E01", "pc/pc.E02", "pc/pc.E03", "usb/usb.e01",
        "split/disk.001", "split/disk.002",
        "vm/disk.vmdk", "vm/disk-flat.vmdk", "vm/other-s001.vmdk",
        "lost/lost.E02", "plain.dd",
    ])
    assert groups["pc/pc.E01"] == ["pc/pc.E01", "pc/pc.E02", "pc/pc.E03"]
    assert groups["usb/usb.e01"] == ["usb/usb.e01"]
    assert groups["split/disk.001"] == ["split/disk.001", "split/disk.002"]
    assert groups["vm/disk.vmdk"] == ["vm/disk-flat.vmdk", "vm/disk.vmdk"]
    assert "vm/other-s001.vmdk" in groups  # no descriptor: opened on its own
    assert groups["plain.dd"] == ["plain.dd"]
    assert orphans == ["lost/lost.E02"]


def test_triage_recognises_raw_and_split_images_by_boot_sector(tmp_path: Path) -> None:
    sector = bytearray(1024)
    sector[510:512] = b"\x55\xaa"
    (tmp_path / "disk.001").write_bytes(bytes(sector))
    (tmp_path / "disk.002").write_bytes(b"\x13" * 1024)
    (tmp_path / "usb.raw").write_bytes(bytes(sector))
    (tmp_path / "notes.001").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 600)
    for name in ("disk.001", "disk.002", "usb.raw"):
        assert classify(tmp_path / name, 1024) == "disk_image", name
    assert classify(tmp_path / "notes.001", 606) != "disk_image"


@pytest.mark.parametrize("name", ["", ".", "..", "CON", "con.txt", "LPT1", "a:b", "a\\b", "a/b", "x\x01y",
                                  "trailing.", "trailing ", "a!b", "q?", "x" * 256])
def test_unsafe_names_are_refused(name: str) -> None:
    with pytest.raises(SecurityError):
        safe_component(name)


@pytest.mark.parametrize("name", ["$Recycle.Bin", "$IABC123.docx", "NTUSER.DAT", "User Data", "CONSOLE.txt", "comX"])
def test_ordinary_names_are_kept(name: str) -> None:
    assert safe_component(name) == name


def test_budget_refuses_large_files_and_stops_at_limits() -> None:
    budget = DiskBudget(total_bytes=100, max_files=2, file_bytes=60)
    assert "per-file" in budget.refusal(61)
    budget.take(50)
    assert "byte budget" in budget.refusal(51)
    budget.take(10)
    assert "file-count" in budget.refusal(1)
    with pytest.raises(SecurityError):
        budget.take(1)


def test_missing_extra_is_a_coverage_gap_not_a_crash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "dissect.target", None)  # import of dissect.target now fails
    ok, why = disk_support()
    assert not ok and "install the disk extra" in why
    with pytest.raises(SecurityError, match="install the disk extra"):
        open_image(tmp_path / "x.dd")

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "pc.dd").write_bytes(b"\0" * 4096)
    plan = {p.name: p for p in plan_agents(profile_evidence(evidence), agents_module.agent_availability())}
    assert not plan["disk_image"].run and "install the disk extra" in plan["disk_image"].reason

    draft = start(input_dir=evidence, output_dir=tmp_path / "run", case_id="nodisk", llm="off")
    gap = next(g for g in draft["coverage_gaps"] if g["what"] == "pc.dd")
    assert "install the disk extra" in gap["why"]
    assert not (tmp_path / "run" / "disk").exists()


# --------------------------------------------------------------------------
# With dissect: a generated FAT image with a Windows folder layout
# --------------------------------------------------------------------------


def test_artefacts_are_copied_hashed_and_cited(tmp_path: Path) -> None:
    _needs_dissect()
    image = build_fat_image(tmp_path / "pc.dd", _windows_tree())
    result = read_image(image, "cases/pc.dd", "a" * 64, tmp_path / "out")
    by_member = {m.member: m for m in result.members}
    expected = {
        "/C:/Windows/System32/winevt/Logs/Application.evtx": "event_log",
        "/C:/Windows/System32/config/SYSTEM": "registry",
        "/C:/Users/alice/NTUSER.DAT": "registry",
        "/C:/Windows/Prefetch/CALC.EXE-12345678.pf": "prefetch",
        "/C:/Users/alice/AppData/Roaming/Microsoft/Windows/Recent/report.lnk": "lnk",
        f"/C:/Users/alice/{HISTORY}": "powershell",
        "/C:/Windows/System32/Tasks/Updater": "scheduled_task",
        "/C:/Windows/inf/setupapi.dev.log": "usb",
        "/C:/$Recycle.Bin/S-1-5-21-1001/$IABC123.docx": "recycle_bin",
    }
    assert {name: by_member[name].category for name in expected} == expected
    assert len(result.members) == len(expected)  # documents and $R content files stay in the image
    history = by_member[f"/C:/Users/alice/{HISTORY}"]
    assert history.cited_as == f"cases/pc.dd!/C:/Users/alice/{HISTORY}"
    copy = tmp_path / "out" / "files" / history.extracted
    assert history.extracted == f"C/Users/alice/{HISTORY}"
    assert hashlib.sha256(copy.read_bytes()).hexdigest() == history.sha256
    assert result.summary["properties"]["os"] == "windows"
    assert result.summary["user_folders"] == ["/C:/Users/alice"]
    assert result.summary["volumes"] == [{"label": "C:", "filesystem": "fat"}]


def test_budget_and_unsafe_names_inside_an_image_become_gaps(tmp_path: Path) -> None:
    _needs_dissect()
    tree = _windows_tree(**{"CON": b"device", "Nightly": b"<Task/>", "NIGHTLY": b"<Task/>", "bad:name": b"x"})
    image = build_fat_image(tmp_path / "pc.dd", tree)
    budget = DiskBudget(total_bytes=10_000, max_files=4, file_bytes=100)
    result = read_image(image, "pc.dd", "b" * 64, tmp_path / "out", budget)
    names = {m.member for m in result.members}
    assert len(names) == 4
    whys = " | ".join(g["why"] for g in result.gaps)
    assert "file-count budget" in whys
    assert "cannot be stored safely" in whys
    assert "differ only by case" in whys
    for gap in result.gaps:
        assert "CON" not in gap["what"] and "bad:name" not in gap["what"]
    assert not any(path.name in {"CON", "bad:name"} for path in (tmp_path / "out").rglob("*"))


def test_autopilot_reads_an_image_and_verifies_its_citations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _needs_dissect()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    build_fat_image(evidence / "pc.dd", _windows_tree())
    before = {p.name: p.read_bytes() for p in evidence.iterdir()}

    real_sha256_file = agents_module.sha256_file

    def no_second_pass(path: Path) -> str:
        assert Path(path).name != "pc.dd", "the image is hashed once, in the custody record"
        return real_sha256_file(path)

    monkeypatch.setattr(agents_module, "sha256_file", no_second_pass)
    draft = start(input_dir=evidence, output_dir=tmp_path / "run", case_id="disk", llm="mock")

    assert {p.name: p.read_bytes() for p in evidence.iterdir()} == before
    disk_agent = next(a for a in draft["agents"] if a["name"] == "disk_image")
    assert disk_agent["status"] == "ok", disk_agent["detail"]
    cited = f"pc.dd!/C:/Users/alice/{HISTORY}"
    secrets = [f for f in draft["findings"] if any(c["source_file"] == cited for c in f["citations"])]
    assert secrets and all(f["verification"] == "row re-read" for f in secrets)
    assert not any(d["worker"] == "disk_image" for d in draft["dropped"])

    members = json.loads((tmp_path / "run" / "disk" / "disk_images.json").read_text())
    assert cited in {m["cited_as"] for m in members}
    summary = json.loads((tmp_path / "run" / "disk" / members[0]["folder"] / "disk_summary.json").read_text())
    assert summary["image"] == "pc.dd" and summary["segments"][0]["path"] == "pc.dd"
    custody = json.loads((tmp_path / "run" / "custody.json").read_text())
    assert summary["image_sha256"] == custody["files"][0]["sha256"]
    text = (tmp_path / "run" / DRAFT_JSON).read_text() + (tmp_path / "run" / DRAFT_MD).read_text()
    assert CANARY not in text
    assert not any("not mounted" in g["why"] for g in draft["coverage_gaps"])


def test_coordinator_drops_a_finding_when_the_copy_changes(tmp_path: Path) -> None:
    _needs_dissect()
    from auto_forensics.models import Citation, Finding
    from auto_forensics_autopilot.coordinator import verify_agent_finding

    image = build_fat_image(tmp_path / "pc.dd", _windows_tree())
    result = read_image(image, "pc.dd", "c" * 64, tmp_path / "out")
    member = next(m for m in result.members if m.category == "powershell")
    copy = tmp_path / "out" / "files" / member.extracted
    line = "mimikatz sekurlsa::logonpasswords"
    finding = Finding(finding_id="f1", title="t", severity="high", confidence=0.7, tactic="credential-access",
                      evidence=[f"line_sha256={agents_module.line_digest(line)}", "decoding=bytes"],
                      citations=[Citation("file-x", member.cited_as, member.sha256, row=2)])
    finding.worker = "disk_image"
    inventory = {member.cited_as: member.sha256}
    locate = {member.cited_as: copy}
    assert verify_agent_finding(finding, tmp_path, inventory, locate) is None
    copy.write_bytes(b"whoami\nsomething else\n")
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == "cited row does not match the agent's record"


# --------------------------------------------------------------------------
# Online only: a real five-segment EnCase image from dissect's test data
# --------------------------------------------------------------------------

EWF_BASE = "https://media.githubusercontent.com/media/fox-it/dissect.evidence/main/tests/_data/ewf/segmented/"
EWF_SEGMENTS = {
    "image.E01": "dff882f955c5cccb79690e9f5be42125c8b5875052f1d3d1dda1d7de597fb6c8",
    "image.E02": "9bd439cdbb5158c1bbc4c12ccac98dc874655573977214763895eb043004f32e",
    "image.E03": "35bc51ba09665794b3852cfe57b9415c7aca901185e64abcd22e90c8b6ebb361",
    "image.E04": "b4823add0c226c42255be4c2cc09ee80cce4f03f107c8c2c7b84e48a46449fce",
    "image.E05": "78844b5d5b80695ba6d8c0901c28820389ebd6bacb0330a934ca01ec06bcd8d1",
}


def test_segmented_e01_is_opened_from_its_first_segment(tmp_path: Path) -> None:
    _needs_dissect()
    folder = tmp_path / "ewf"
    folder.mkdir()
    for name, digest in EWF_SEGMENTS.items():
        try:
            with urllib.request.urlopen(EWF_BASE + name, timeout=15) as response:
                data = response.read(4 * 1024 * 1024)
        except OSError as exc:
            pytest.skip(f"offline: {type(exc).__name__}")
        if hashlib.sha256(data).hexdigest() != digest:
            pytest.skip("sample image changed upstream")
        (folder / name).write_bytes(data)
    groups, orphans = group_images(sorted(EWF_SEGMENTS))
    assert list(groups) == ["image.E01"] and not orphans
    assert all(classify(folder / name, 1) == "disk_image" for name in EWF_SEGMENTS)
    target = open_image(folder / "image.E01")
    size = target.disks[0].size
    assert size > max((folder / name).stat().st_size for name in EWF_SEGMENTS)  # read across segments
    result = read_image(folder / "image.E01", "image.E01", EWF_SEGMENTS["image.E01"], tmp_path / "out")
    assert result.members == []
    assert any("no readable filesystem" in g["why"] for g in result.gaps)


NTFS_SAMPLE = "https://media.githubusercontent.com/media/fox-it/dissect.ntfs/main/tests/_data/ntfs.bin.gz"
NTFS_SHA256 = "cc1b5c665a80befed008b3db817325aac1555e1efe511de63203f421c2250080"


def test_real_ntfs_volume_is_listed_and_mft_is_opt_in(tmp_path: Path) -> None:
    _needs_dissect()
    import gzip

    try:
        with urllib.request.urlopen(NTFS_SAMPLE, timeout=15) as response:
            packed = response.read(2 * 1024 * 1024)
    except OSError as exc:
        pytest.skip(f"offline: {type(exc).__name__}")
    if hashlib.sha256(packed).hexdigest() != NTFS_SHA256:
        pytest.skip("sample image changed upstream")
    image = tmp_path / "volume.img"
    image.write_bytes(gzip.decompress(packed))
    plain = read_image(image, "volume.img", "d" * 64, tmp_path / "plain")
    assert plain.members == []
    assert plain.summary["volumes"] == [{"label": "fs0", "filesystem": "ntfs"}]
    assert "/fs0/File.txt" in {row["path"] for row in plain.summary["listing"]["rows"]}
    with_mft = read_image(image, "volume.img", "d" * 64, tmp_path / "mft", include_mft=True)
    assert [m.cited_as for m in with_mft.members] == ["volume.img!/fs0/$MFT"]


def test_module_never_imports_dissect_at_import_time() -> None:
    assert "dissect" not in disk_images.__dict__
