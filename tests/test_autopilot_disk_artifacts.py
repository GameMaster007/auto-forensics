"""Disk artefacts: parsers checked against real Windows files, detections, and citation re-checks.

Tests that need a real artefact download it from a pinned commit (see
``_real_samples``) and are skipped offline. Tests of the detection logic
build small artefacts by hand; where a test uses a hand-built file it says so.
"""

from __future__ import annotations

import hashlib
import json
import random
import sqlite3
import struct
import sys
from pathlib import Path

import pytest

from auto_forensics.models import Finding
from auto_forensics_autopilot import agents as agents_module
from auto_forensics_autopilot import disk_artifacts as da
from auto_forensics_autopilot import disk_parsers as dp
from auto_forensics_autopilot import disk_registry as dr
from auto_forensics_autopilot.coordinator import merge_findings, verify_agent_finding
from auto_forensics_autopilot.disk_images import DiskMember
from auto_forensics_autopilot.orchestrator import DRAFT_JSON, DRAFT_MD, start
from auto_forensics_autopilot.triage import plan_agents, profile_evidence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _fat_image import build_fat_image  # noqa: E402
from _real_samples import sample  # noqa: E402

CANARY = "CANARY-art1fact-42"
RECENT = "AppData/Roaming/Microsoft/Windows/Recent"


def _by_kind(records: list[dp.Record], kind: str) -> list[dp.Record]:
    return [record for record in records if record.kind == kind]


def _all_locators_reread(path: Path, records: list[dp.Record]) -> None:
    """Every record's location can be read back from the file and hashed."""
    with dp.Rereader() as rereader:
        for record in records:
            assert rereader.digest(path, record.locator), (record.kind, record.locator)


# --------------------------------------------------------------------------
# Registry: real hives
# --------------------------------------------------------------------------


def test_hive_reader_agrees_with_dissect_on_a_real_hive() -> None:
    regf = pytest.importorskip("dissect.regf.regf")
    path = sample("NTUSER-WIN7")

    def ours(key: dp.RegKey, depth: int) -> dict:
        return {"values": {v.name: v.data for v in key.values()},
                "keys": {k.name: ours(k, depth + 1) for k in key.subkeys()} if depth < 12 else {}}

    def theirs(key, depth: int) -> dict:  # noqa: ANN001
        return {"values": {v.name if v.name != "(Default)" else "": v.data for v in key.values()},
                "keys": {k.name: theirs(k, depth + 1) for k in key.subkeys()} if depth < 12 else {}}

    with dp.Hive(path) as hive, path.open("rb") as handle:
        reference = regf.RegistryHive(handle)
        mine = ours(hive.open("Software\\Microsoft\\Windows\\CurrentVersion"), 0)
        expected = theirs(reference.open("Software\\Microsoft\\Windows\\CurrentVersion"), 0)
    assert mine == expected
    assert len(mine["keys"]["Explorer"]["keys"]) > 20


def test_real_windows7_system_hive_gives_the_usb_stick_and_system_facts() -> None:
    path = sample("SYSTEM")
    records, problems = dr.parse_hive(path, "system")
    assert problems == []
    _all_locators_reread(path, records)
    (device,) = _by_kind(records, "usb_device")
    assert device.fields["vendor"] == "HP" and device.fields["product"] == "v100w"
    assert device.fields["serial"] == "AA951D0000007252" and device.fields["serial_is_unique"] is True
    assert device.fields["friendly_name"] == "HP v100w USB Device"
    assert device.fields["first_install"] == "2011-04-01T04:52:38Z"
    assert device.locator.startswith("regk:")
    names = {r.fields.get("volume_name") for r in _by_kind(records, "usb_volume_name")}
    assert "SECRETPLANS" in names
    mounted = {r.fields["mount"]: r.fields for r in _by_kind(records, "mounted_device")}
    assert mounted["E:"]["is_usb"] is True and mounted["E:"]["serial"] == "AA951D0000007252"
    assert mounted["D:"]["is_optical"] is True and mounted["C:"]["is_usb"] is False
    facts = {r.fields["fact"]: r for r in _by_kind(records, "system_fact")}
    assert facts["time_zone"].fields["value"] == "Eastern Standard Time"
    assert facts["time_zone"].fields["bias_minutes"] == 300 and facts["time_zone"].fields["active_bias_minutes"] == 240
    assert facts["last_shutdown"].time == "2012-04-04T01:58:40Z"
    assert facts["computer_name"].fields["value"] == "WKS-WIN732BITA"
    assert len(_by_kind(records, "optical_drive")) == 4


def test_real_windows10_system_hive_gives_connect_and_removal_times() -> None:
    # The values regipy's own USBSTOR test expects for this hive.
    records, _ = dr.parse_hive(sample("SYSTEM-WIN10"), "system")
    (device,) = _by_kind(records, "usb_device")
    assert (device.fields["vendor"], device.fields["product"], device.fields["revision"]) == ("SanDisk", "Cruzer", "1.20")
    assert device.fields["serial"] == "200608767007B7C08A6A"
    assert device.fields["last_arrival"] == "2020-03-17T14:02:38Z"
    assert device.fields["last_removal"] == "2020-03-17T14:23:45Z"
    (bus,) = _by_kind(records, "usb_bus_device")
    assert (bus.fields["vendor_id"], bus.fields["product_id"]) == ("0781", "5530")


def test_real_software_hive_gives_install_date_programs_and_usb_volume_serial() -> None:
    path = sample("SOFTWARE")
    records, problems = dr.parse_hive(path, "software")
    assert problems == []
    _all_locators_reread(path, records)
    facts = {r.fields["fact"]: r for r in _by_kind(records, "system_fact")}
    assert facts["os_install_date"].time == "2010-11-10T16:28:55Z"
    assert facts["os_version"].fields["value"] == "Windows 7 Ultimate"
    assert facts["os_version"].fields["service_pack"] == "Service Pack 1"
    programs = {r.fields["name"] for r in _by_kind(records, "installed_program")}
    assert {"Mozilla Firefox 5.0.1 (x86 en-US)", "Adobe AIR", "Microsoft Office Home and Business 2010"} <= programs
    boost = [r for r in _by_kind(records, "usb_volume_name") if r.fields.get("source") == "EMDMgmt"]
    assert [(r.fields["volume_name"], r.fields["volume_serial"], r.fields["serial"]) for r in boost] == [
        ("SECRETPLANS", "B844-79ED", "AA951D0000007252")]
    profiles = {r.fields["path"] for r in _by_kind(records, "user_profile")}
    assert "C:\\Users\\nfury" in profiles
    assert any(r.fields["name"] == "Microsoft Outlook" for r in _by_kind(records, "mail_client"))


def test_real_windows7_user_hive_gives_shares_recent_files_and_program_runs() -> None:
    path = sample("NTUSER-WIN7")
    records, problems = dr.parse_hive(path, "ntuser")
    assert problems == []
    _all_locators_reread(path, records)
    (drive,) = _by_kind(records, "mapped_drive")
    assert (drive.fields["drive"], drive.fields["share"]) == ("P:", "\\\\controller\\public")
    shares = {r.fields["share"] for r in _by_kind(records, "mount_point") if r.fields["mount_type"] == "network"}
    assert shares == {"\\\\controller\\home\\nfury", "\\\\controller\\public"}
    assert [r.fields["path"] for r in _by_kind(records, "typed_path")] == ["\\\\controller"]
    assert {r.fields["term"] for r in _by_kind(records, "explorer_search")} == {"hyth", "rar.exe"}
    recent = {r.fields["name"] for r in _by_kind(records, "recent_doc")}
    assert {"StarFury.zip", "VIBRANIUM.docx", "wallpaper_medium.jpg"} <= recent
    dialogs = {r.fields["path"] for r in _by_kind(records, "open_save")}
    assert "P:\\Application Tools\\Firefox 6.0\\Firefox Setup 6.0.exe" in dialogs
    assert "\\\\controller\\WebDavShare\\Firefox Setup 3.6.12.exe" in dialogs
    office = {r.fields["path"]: r.time for r in _by_kind(records, "office_mru")}
    assert office["C:\\Users\\nfury\\Documents\\StarFury\\StarFury\\SA-23E Mitchell-Hyundyne Starfury.docx"] == \
        "2012-03-13T18:27:15Z"
    runs = {r.fields["program"]: r.fields for r in _by_kind(records, "user_assist")}
    assert runs["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\calc.exe"]["run_count"] == 12  # ROT13 decoded
    (store,) = _by_kind(records, "mail_store")
    assert store.fields["path"].endswith("nfury@stark-research-labs.com.pst")
    assert [r.fields["program"] for r in _by_kind(records, "program_key")] == ["BCWipe"]
    (staging,) = [r for r in _by_kind(records, "cd_burning") if r.fields["what"] == "staging folder"]
    assert staging.fields["staging_path"].endswith("\\Microsoft\\Windows\\Burn\\Burn")


def test_real_xp_user_hive_and_ccleaner_hive() -> None:
    records, _ = dr.parse_hive(sample("NTUSER-XP"), "ntuser")
    assert "Very secret document.txt" in {r.fields["name"] for r in _by_kind(records, "recent_doc")}
    assert any(r.fields["run_count"] > 0 and r.time for r in _by_kind(records, "user_assist"))  # 16-byte XP entries
    cleaner, _ = dr.parse_hive(sample("NTUSER-CCLEANER"), "ntuser")
    (key,) = [r for r in _by_kind(cleaner, "program_key") if r.fields["program"] == "CCleaner"]
    assert key.time == "2013-07-13T14:03:26Z" and key.fields["key_path"] == "Software\\Piriform\\CCleaner"


def test_real_sam_hive_gives_accounts() -> None:
    records, _ = dr.parse_hive(sample("SAM"), "sam")
    accounts = {r.fields["name"]: r.fields for r in records}
    assert set(accounts) == {"Administrator", "Guest", "gold_administrator"}
    assert accounts["Administrator"]["rid"] == 500 and accounts["Administrator"]["disabled"] is True
    assert accounts["gold_administrator"]["rid"] == 1001
    assert accounts["gold_administrator"]["last_logon"] == "2016-10-11T19:52:35Z"
    assert accounts["gold_administrator"]["logon_count"] == 4


def test_real_shellbags_and_archive_history() -> None:
    records, problems = dr.parse_hive(sample("NTUSER-BAGMRU"), "ntuser")
    assert any("not cleanly saved" in problem for problem in problems)  # this hive is "dirty"; that is reported
    folders = {r.fields["path"] for r in _by_kind(records, "shellbag")}
    assert {"\\\\wsl$\\Ubuntu\\root", "\\\\wsl$\\Ubuntu\\tmp"} <= folders and len(folders) > 50
    archives = {r.fields["path"] for r in _by_kind(records, "archive_history")}
    assert "C:\\Users\\tony\\Downloads\\RegistryExplorer.zip" in archives
    assert {"OneDrive", "WinRAR", "7-Zip", "WinSCP"} <= {r.fields["program"] for r in _by_kind(records, "program_key")}


# --------------------------------------------------------------------------
# Shortcuts, Jump Lists, Prefetch, Recycle Bin: real files
# --------------------------------------------------------------------------


def test_real_shortcuts() -> None:
    path = sample("nero.lnk")
    (record,) = dp.parse_lnk(path)
    fields = record.fields
    assert fields["target_path"] == "C:\\Program Files (x86)\\Nero\\Nero 9\\Nero InfoTool\\InfoTool.exe"
    assert (fields["drive_type"], fields["volume_serial"], fields["volume_label"]) == ("fixed", "70EC-FA33", "OS")
    assert fields["target_size"] == 4635160 and fields["target_modified"] == "2009-06-05T20:13:20Z"
    assert fields["arguments"] == "-ScParameter=30002" and fields["machine_id"] == "win-3qmdjgkf3g9"
    assert record.locator == f"bytes:0:{path.stat().st_size}"
    _all_locators_reread(path, [record])
    (other,) = dp.parse_lnk(sample("example.lnk"))
    assert other.fields["machine_id"] == "win-tj9qcsjkags" and other.fields["mac_address"] == "00:1d:09:fa:5a:1c"
    assert other.fields["target_created"] == "2009-07-13T23:29:02Z"


def test_real_jump_lists() -> None:
    path = sample("auto-win7.jump")
    records = dp.parse_automatic_destinations(path)
    _all_locators_reread(path, records)
    by_path = {r.fields["target_path"]: r for r in records}
    assert len(records) == 7
    poultry = by_path["C:\\Users\\bperry\\Documents\\Poultry Studies"]
    assert poultry.time == "2015-08-25T12:12:39Z"  # last use, from the DestList stream
    assert poultry.fields["host"] == "student-pc1" and poultry.fields["drive_type"] == "fixed"
    assert poultry.locator.startswith("bytes:") and poultry.locator.endswith(":128")
    win10 = dp.parse_automatic_destinations(sample("auto-win10.jump"))
    assert [(r.fields["dest_path"], r.fields["use_count"], r.time) for r in win10] == [
        ("http://go.microsoft.com/fwlink/?linkid=624682&clcid=0x409&campaign=ct!!31DAEFFBA6804D2599B337798559C7F4",
         1, "2015-12-27T20:10:04Z"),
        ("http://support.microsoft.com/kb/3124263", 1, "2016-01-17T13:08:08Z")]
    custom_path = sample("custom.jump")
    custom = dp.parse_custom_destinations(custom_path)
    _all_locators_reread(custom_path, custom)
    assert len(custom) == 9 and all(r.time is None for r in custom)
    assert {r.fields["target_path"] for r in custom} == {"C:\\Windows\\System32\\GettingStarted.exe"}


@pytest.mark.parametrize(("name", "program", "version", "runs", "last", "compressed"), [
    ("CMD.pf", "CMD.EXE", 17, 2, "2013-03-10T10:11:49Z", False),
    ("PING.pf", "PING.EXE", 23, 14, "2012-04-06T19:00:55Z", False),
    ("TASKHOST.pf", "TASKHOST.EXE", 26, 4, "2013-10-04T15:40:09Z", False),
    ("NOTEPAD.pf", "NOTEPAD.EXE", 30, 2, "2019-06-05T19:55:04Z", True),
    ("ONEDRIVE.pf", "ONEDRIVE.EXE", 30, 2, "2015-05-14T22:11:05Z", True),
])
def test_real_prefetch_files(name: str, program: str, version: int, runs: int, last: str, compressed: bool) -> None:
    if compressed:
        pytest.importorskip("dissect.util")
    path = sample(name)
    (record,) = dp.parse_prefetch(path)
    fields = record.fields
    assert (fields["program"], fields["format_version"], fields["run_count"]) == (program, version, runs)
    assert record.time == last and fields["last_runs"][0] == last and fields["compressed"] is compressed
    assert fields["volumes"] and fields["files_referenced"] > 10
    # A compressed file has no offsets of its own to cite, and says so.
    assert record.locator == ("file" if compressed else record.locator) and (record.locator == "file") is compressed
    _all_locators_reread(path, [record])


def test_real_recycle_bin_index_files() -> None:
    (old,) = dp.parse_recycle_index(sample("$II3DF3L.zip"))
    assert old.fields["original_path"] == "C:\\Users\\nfury\\Documents\\Alloy Research\\StarFury.zip"
    assert old.fields["size_bytes"] == 724919 and old.time == "2012-03-12T20:49:58Z"
    (new,) = dp.parse_recycle_index(sample("$I103S5F.jpg"))  # Windows 10 layout
    assert new.fields["original_path"] == "C:\\Users\\random\\Downloads\\bunnies.jpg"
    assert new.fields["size_bytes"] == 222255 and new.time == "2016-06-29T21:37:45Z"


# --------------------------------------------------------------------------
# Browser history and cloud client: real databases
# --------------------------------------------------------------------------


def test_real_chrome_history() -> None:
    path = sample("chrome-History")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    records = dp.parse_chromium_history(path)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before  # opened from a temporary copy, never written
    assert not list(path.parent.glob("History-*"))  # no journal or WAL beside it
    _all_locators_reread(path, records)
    assert len(_by_kind(records, "browser_visit")) == 69
    searches = {r.fields["term"] for r in _by_kind(records, "web_search")}
    assert {"funny cats", "really really funny cats", "funnycats.exe"} <= searches
    downloads = {r.fields["target_path"]: r for r in _by_kind(records, "browser_download")}
    assert downloads["/home/john/Downloads/funcats_scr.exe"].fields["size_bytes"] == 1132155
    assert downloads["/home/john/Downloads/funcats_scr.exe"].time == "2011-05-23T08:35:30Z"
    newer = dp.parse_chromium_history(sample("chrome59-History"))
    (state,) = _by_kind(newer, "browser_table_state")
    assert state.fields == {"browser": "chrome", "table": "urls", "rows_ever": 1, "rows_now": 1}
    (download,) = _by_kind(newer, "browser_download")
    assert download.time == "2018-01-21T14:08:51Z" and download.fields["host"] == "raw.githubusercontent.com"


def test_real_firefox_history() -> None:
    path = sample("firefox25-places")
    records = dp.parse_firefox_places(path)
    _all_locators_reread(path, records)
    assert len(_by_kind(records, "browser_visit")) == 34
    assert [r.fields["term"] for r in _by_kind(records, "web_search")] == ["the onion"]
    (download,) = _by_kind(records, "browser_download")
    assert download.fields["host"] == "googledrive.com" and download.time == "2013-10-30T21:58:24Z"
    modern = dp.parse_firefox_places(sample("firefox118-places"))
    assert "python download" in {r.fields["term"] for r in _by_kind(modern, "web_search")}
    assert len(_by_kind(modern, "browser_download")) == 7


def test_real_internet_explorer_index_dat() -> None:
    path = sample("index.dat")
    records = dp.parse_index_dat(path)
    _all_locators_reread(path, records)
    visits = {r.fields["url"]: r for r in _by_kind(records, "browser_visit")}
    assert visits["http://www.msn.com/?ocid=iehp"].time == "2015-08-25T11:05:18Z"
    assert {r.fields["term"] for r in _by_kind(records, "web_search")} == {"ie 11"}


def test_real_internet_explorer_webcache() -> None:
    pytest.importorskip("dissect.database")
    path = sample("WebCacheV01.dat")
    problems: list[str] = []

    class Clock:
        """Stands in for the time limit: counts the checks, and "runs out" after ``left`` of them."""

        def __init__(self, left: int) -> None:
            self.left, self.checks = left, 0

        def check(self) -> None:
            self.checks += 1
            if self.checks > self.left:
                raise dp.ParseBudget("time limit reached")

    counting = Clock(10**9)
    records = dp.parse_webcache(path, counting)
    partial = dp.parse_webcache(path, Clock(counting.checks - 20), problems)  # stop just before the end
    assert 0 < len(partial) < len(records)
    assert len(problems) == 1 and "stopped early (time limit reached)" in problems[0]
    visits = _by_kind(records, "browser_visit")
    assert len(visits) > 100 and all(r.locator == "file" for r in records)  # honest: no smaller location
    assert any(r.fields["host"] == "www.forensicswiki.org" and r.time and r.time.startswith("2014-05-12")
               for r in visits)


def test_real_google_drive_snapshot() -> None:
    path = sample("gdrive-snapshot.db")
    records = dp.parse_gdrive_snapshot(path)
    _all_locators_reread(path, records)
    cloud = {r.fields["name"]: r for r in records if r.fields["side"] == "cloud"}
    assert cloud["My Super Secret Document (in the root folder)"].time == "2014-01-28T00:09:21Z"
    local = {r.fields["name"] for r in records if r.fields["side"] == "local"}
    assert "Don't Let Anyone Discover Me - ultra secret.gsheet" in local


def test_real_setupapi_log_sections_and_clock_check() -> None:
    path = sample("setupapi.dev.log")
    records = dp.parse_setupapi(path)
    _all_locators_reread(path, records)
    sections = _by_kind(records, "setup_section")
    assert len(sections) == 194 and sections[0].fields["local_time"] == "2015-11-22T17:59:28"
    assert _by_kind(records, "device_install") == []  # this Windows 10 log has no USB storage installs
    span = dp.read_span(path, *[int(part) for part in sections[0].locator.split(":")[1:]])
    assert span is not None and span.startswith(b">>>  [Device Install (Hardware initiated)") and b"Section start" in span


# --------------------------------------------------------------------------
# Hand-built artefacts for the detection logic
# --------------------------------------------------------------------------


def make_lnk(target: str, *, drive_type: int = 2, serial: int = 0x1234ABCD, label: str = "USB",
             accessed: int = 130_700_000_000_000_000) -> bytes:
    """A minimal shortcut with a LinkInfo block (hand-built; real shortcuts are tested above)."""
    base = target.encode("latin-1") + b"\0"
    volume_label = label.encode("latin-1") + b"\0"
    volume = struct.pack("<4I", 16 + len(volume_label), drive_type, serial, 16) + volume_label
    header_size = 0x1C
    info_body = volume + base + b"\0"
    info = struct.pack("<7I", header_size + len(info_body), header_size, 1, header_size, header_size + len(volume), 0,
                       header_size + len(volume) + len(base)) + info_body
    header = (dp.LNK_MAGIC + struct.pack("<II", 0x2, 0x20) + struct.pack("<QQQ", accessed, accessed, accessed)
              + struct.pack("<IIIH", 1000, 0, 1, 0) + b"\0" * 10)
    assert len(header) == 76
    return header + info + b"\0\0\0\0"


def make_recycle_index(path: str, deleted: int, size: int = 4096) -> bytes:
    text = (path + "\0").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, deleted, len(path) + 1) + text


SETUPAPI = (
    b"[Device Install Log]\r\n     OS Version = 6.1.7601\r\n\r\n"
    b">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01\\"
    b"4C530012450531101593&0]\r\n>>>  Section start 2015/03/23 14:31:10.123\r\n     ump: Creating Install Process\r\n"
    b"<<<  Section end 2015/03/23 14:31:12.000\r\n<<<  [Exit status: SUCCESS]\r\n\r\n"
    b">>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Fit&Rev_2.01\\"
    b"4C530012550531106501&0]\r\n>>>  Section start 2015/03/24 09:38:00.500\r\n<<<  [Exit status: SUCCESS]\r\n"
)


def stage(tmp_path: Path, files: dict[str, tuple[str, bytes]], modified: dict[str, str] | None = None
          ) -> tuple[Path, list[DiskMember]]:
    """Write ``{path in image: (category, bytes)}`` the way the disk-image agent lays copies out."""
    image_dir = tmp_path / "disk" / "pc-00000000-00000000"
    members = []
    for member, (category, data) in files.items():
        rel = "C/" + member
        out = image_dir / "files" / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        members.append(DiskMember("pc.dd", "a" * 64, "/C:/" + member, rel, hashlib.sha256(data).hexdigest(),
                                  len(data), category, (modified or {}).get(member, "")))
    return image_dir, members


def run_analysis(tmp_path: Path, files: dict[str, tuple[str, bytes]], modified: dict[str, str] | None = None):
    image_dir, members = stage(tmp_path, files, modified)
    outcome = da.analyse_image("pc.dd", image_dir, members)
    for finding in outcome.findings:
        finding.worker = da.WORKER
    inventory = {member.cited_as: member.sha256 for member in members}
    locate = {member.cited_as: image_dir / "files" / member.extracted for member in members}
    return outcome, inventory, locate


def _titles(outcome: da.Outcome) -> list[str]:
    return [finding.title for finding in outcome.findings]


def _one(outcome: da.Outcome, start: str) -> Finding:
    found = [finding for finding in outcome.findings if finding.title.startswith(start)]
    assert len(found) == 1, (start, _titles(outcome))
    return found[0]


def test_watch_lists_match_whole_words_only() -> None:
    assert da.match_program("CCLEANER64.EXE") == ("anti_forensics", "CCleaner", "T1070")
    assert da.match_program("C:\\Program Files\\Eraser\\Eraser.exe")[1] == "Eraser"
    assert da.match_program("NeroInfoTool.exe")[1] == "Nero"
    assert da.match_program("generous.exe") is None and da.match_program("dinero.exe") is None
    assert da.match_program("GOOGLEDRIVESYNC.EXE")[:2] == ("cloud_storage", "Google Drive")
    assert da.match_domain("drive.google.com") == "cloud_storage" and da.match_domain("mail.google.com") == "webmail"
    assert da.match_domain("notdropbox.com") is None and da.match_domain("www.dropbox.com") == "cloud_storage"
    assert "anti_forensics" in da.match_search("anti-forensic tools") and "data_leak" in da.match_search(
        "how to leak a secret")
    assert da.match_search("weather tomorrow") == []
    assert da.looks_confidential("[secret_project]_pricing_decision.xlsx") and da.looks_confidential("Design.pptx")
    assert not da.looks_confidential("redesigned-holiday.jpg") and not da.looks_confidential("notes.txt")


def test_files_on_removable_media_burst_and_confidential_names(tmp_path: Path) -> None:
    names = ["[secret_project]_pricing_decision.xlsx", "(secret_project)_design_concept.ppt", "holiday.jpg",
             "budget.docx", "cars.db", "notes.txt"]
    files = {}
    modified = {}
    for index, name in enumerate(names):
        member = f"Users/informant/{RECENT}/{index}.lnk"
        files[member] = ("lnk", make_lnk(f"E:\\RM#1\\{name}", serial=0x2CA3D1AE))
        modified[member] = f"2015-03-24T13:4{index}:00Z"
    files[f"Users/informant/{RECENT}/cd.lnk"] = ("lnk", make_lnk("D:\\de\\winter_storm.amr", drive_type=5,
                                                                 serial=0x0B0A0908, label="Mar 24 2015"))
    files[f"Users/informant/{RECENT}/local.lnk"] = ("lnk", make_lnk("C:\\Users\\informant\\Desktop\\todo.txt",
                                                                    drive_type=3))
    outcome, inventory, locate = run_analysis(tmp_path, files, modified)
    removable = _one(outcome, "Files or folders opened on removable media")
    assert "6 paths on one volume" in removable.title and removable.severity == "medium"
    assert removable.technique_id == "T1052.001" and removable.tactic == "exfiltration"
    assert "between 2015-03-24T13:40:00Z and 2015-03-24T13:45:00Z" in removable.title
    burst = _one(outcome, "Many files touched on removable media in a short time")
    assert burst.severity == "high" and "6 different paths within 10 minutes" in burst.title
    secret = _one(outcome, "Confidential-looking file names on removable media")
    assert secret.severity == "high" and "3 names" in secret.title
    disc = _one(outcome, "Files or folders opened on a CD/DVD")
    assert disc.technique_id == "T1052"
    assert not any("todo" in title or "local" in title for title in _titles(outcome))
    # The file names are in the details and the timeline, not in any title.
    assert not any("secret_project" in finding.title or "RM#1" in finding.title for finding in outcome.findings)
    detail = outcome.summary["findings"][secret.finding_id]
    assert {row["path"] for row in detail["files"]} == {f"E:\\RM#1\\{name}" for name in names[:2] + ["budget.docx"]}
    for finding in outcome.findings:
        assert verify_agent_finding(finding, tmp_path, inventory, locate) is None, finding.title
        assert all(citation.offset == 0 for citation in finding.citations)


def test_usb_devices_from_setupapi_use_the_registry_time_zone(tmp_path: Path) -> None:
    # Hand-built log text in the real Windows 7 layout: no public sample with USB storage sections was found.
    outcome, inventory, locate = run_analysis(tmp_path, {"Windows/inf/setupapi.dev.log": ("usb", SETUPAPI)})
    assert sorted(title[:44] for title in _titles(outcome)) == [
        "USB storage device connected (device 1 of 2)", "USB storage device connected (device 2 of 2)"]
    devices = outcome.summary["usb_devices"]
    assert [d["serial"] for d in devices] == ["4C530012450531101593", "4C530012550531106501"]
    assert devices[0]["vendor"] == "" and devices[0]["first_install_local"] == "2015-03-23T14:31:10"
    assert devices[0]["first_seen"] is None  # no time zone known, so the local time is not passed off as UTC
    finding = _one(outcome, "USB storage device connected (device 1 of 2)")
    assert "4C53" not in finding.title and finding.severity == "low" and finding.technique_id == "T1052.001"
    assert verify_agent_finding(finding, tmp_path, inventory, locate) is None
    (citation,) = finding.citations
    cited = dp.read_span(locate[citation.source_file], citation.offset, 60)
    assert cited is not None and cited.startswith(b">>>  [Device Install (Hardware initiated) - USBSTOR")

    context = da.Context(bias_minutes=240)  # Eastern Daylight Time: UTC = local + 4 hours
    assert da._local_to_utc("2015-03-23T14:31:10", context.bias_minutes) == "2015-03-23T18:31:10Z"


def test_setupapi_clock_running_backwards_is_reported(tmp_path: Path) -> None:
    log = (b">>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5571\\4C530012450531101593]\r\n"
           b">>>  Section start 2015/03/25 10:00:00.000\r\n<<<  [Exit status: SUCCESS]\r\n"
           b">>>  [Setup Import Driver Package - C:\\x.inf]\r\n>>>  Section start 2015/03/22 08:00:00.000\r\n")
    outcome, inventory, locate = run_analysis(tmp_path, {"Windows/inf/setupapi.dev.log": ("usb", log)})
    finding = _one(outcome, "System clock or time zone changed")
    assert "goes backwards 1 time, by up to 74 hours" in finding.title and finding.technique_id == "T1070.006"
    assert verify_agent_finding(finding, tmp_path, inventory, locate) is None


def test_mass_deletion_and_confidential_names_in_the_recycle_bin(tmp_path: Path) -> None:
    base = 130_716_000_000_000_000  # 2015-03-24
    files = {}
    for index in range(7):
        name = "secret_plans.docx" if index == 0 else f"file{index}.tmp"
        files[f"$Recycle.Bin/S-1-5-21-1-2-3-1000/$IAAAAA{index}.docx"] = (
            "recycle_bin", make_recycle_index(f"C:\\Users\\informant\\Desktop\\{name}", base + index * 10_000_000))
    outcome, inventory, locate = run_analysis(tmp_path, files)
    assert "7 deleted items" in _one(outcome, "Items in the Recycle Bin").title
    mass = _one(outcome, "Mass deletion")
    assert "7 items sent to the Recycle Bin within 10 minutes" in mass.title and mass.technique_id == "T1070.004"
    assert _one(outcome, "Confidential-looking file names among deleted items").severity == "medium"
    assert all(verify_agent_finding(f, tmp_path, inventory, locate) is None for f in outcome.findings)


def make_chrome_history(path: Path, *, clear: bool = False) -> bytes:
    db = sqlite3.connect(path)
    db.executescript(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT, url LONGVARCHAR, title LONGVARCHAR, "
        "visit_count INTEGER DEFAULT 0, typed_count INTEGER DEFAULT 0, last_visit_time INTEGER NOT NULL, "
        "hidden INTEGER DEFAULT 0);"
        "CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT, url INTEGER NOT NULL, visit_time INTEGER NOT NULL, "
        "from_visit INTEGER, transition INTEGER DEFAULT 0, segment_id INTEGER, visit_duration INTEGER DEFAULT 0);"
        "CREATE TABLE keyword_search_terms(keyword_id INTEGER NOT NULL, url_id INTEGER NOT NULL, "
        "term LONGVARCHAR NOT NULL, normalized_term LONGVARCHAR NOT NULL);")
    when = 13_071_600_000_000_000  # 2015-03-23, microseconds since 1601
    pages = ["https://drive.google.com/drive/my-drive", "https://mail.google.com/mail/u/0/#inbox",
             "https://www.google.com/search?q=anti-forensic+tools", "https://www.google.com/search?q=how+to+leak+a+secret",
             "https://www.ccleaner.com/ccleaner/download", "https://www.bbc.co.uk/weather",
             f"https://www.google.com/search?q={CANARY}+data+leakage+methods"]
    for index, url in enumerate(pages, start=1):
        db.execute("INSERT INTO urls(url, title, visit_count, last_visit_time) VALUES (?, ?, 1, ?)",
                   (url, f"page {index}", when + index))
        db.execute("INSERT INTO visits(url, visit_time) VALUES (?, ?)", (index, when + index * 60_000_000))
    db.execute("INSERT INTO keyword_search_terms VALUES (2, 3, 'eraser download', 'eraser download')")
    if clear:
        db.execute("DELETE FROM urls")
        db.execute("DELETE FROM visits")
    db.commit()
    db.close()
    return path.read_bytes()


def test_web_categories_searches_and_cleared_history(tmp_path: Path) -> None:
    history = "Users/informant/AppData/Local/Google/Chrome/User Data/Default/History"
    data = make_chrome_history(tmp_path / "History")  # hand-built in the real Chrome schema
    outcome, inventory, locate = run_analysis(tmp_path / "a", {history: ("browser", data)})
    cloud = _one(outcome, "Web sites for cloud storage visited")
    assert "1 visit to 1 site" in cloud.title and cloud.technique_id == "T1567.002"
    assert _one(outcome, "Web sites for webmail visited").severity == "low"
    assert _one(outcome, "Web sites for anti-forensic or wiping visited").tactic == "defense-evasion"
    wiping = _one(outcome, "Searches about anti-forensic or wiping")
    assert "2 different searches" in wiping.title and wiping.severity == "medium"
    assert "2 different searches" in _one(outcome, "Searches about leaking information").title
    assert not any(CANARY in f.title or "eraser download" in f.title for f in outcome.findings)
    assert any(row["term"].startswith(CANARY) for row in outcome.summary["flagged_searches"])
    assert all(c.row and c.offset is None for f in outcome.findings for c in f.citations)  # database rows
    assert all(verify_agent_finding(f, tmp_path, inventory, locate) is None for f in outcome.findings)
    assert not any("history" in title.lower() for title in _titles(outcome))

    cleared = make_chrome_history(tmp_path / "History2", clear=True)
    outcome, inventory, locate = run_analysis(tmp_path / "b", {history: ("browser", cleared)})
    finding = _one(outcome, "Browser history was cleared")
    assert "2 history tables now empty" in finding.title and finding.technique_id == "T1070"
    assert verify_agent_finding(finding, tmp_path, inventory, locate) is None


def test_real_hives_give_tool_usb_share_and_mail_findings(tmp_path: Path) -> None:
    pytest.importorskip("dissect.util")  # the Windows 10 Prefetch sample is compressed
    files = {
        "Windows/System32/config/SYSTEM": ("registry", sample("SYSTEM").read_bytes()),
        "Windows/System32/config/SAM": ("registry", sample("SAM").read_bytes()),
        "Users/nfury/NTUSER.DAT": ("registry", sample("NTUSER-WIN7").read_bytes()),
        "Users/cleaner/NTUSER.DAT": ("registry", sample("NTUSER-CCLEANER").read_bytes()),
        "Users/kiddi/AppData/Local/Google/Drive/user_default/snapshot.db": ("cloud",
                                                                           sample("gdrive-snapshot.db").read_bytes()),
        "Windows/Prefetch/ONEDRIVE.EXE-7E152375.pf": ("prefetch", sample("ONEDRIVE.pf").read_bytes()),
    }
    outcome, inventory, locate = run_analysis(tmp_path, files)
    usb = _one(outcome, "USB storage device connected (device 1 of 1)")
    assert "between 2011-04-01T04:52:38Z and 2012-04-07T10:31:37Z" in usb.title
    assert len(usb.citations) >= 3 and all(c.offset for c in usb.citations)
    device = outcome.summary["usb_devices"][0]
    assert (device["vendor"], device["product"], device["serial"]) == ("HP", "v100w", "AA951D0000007252")
    assert device["drive_letters"] == ["E:"] and device["volume_names"] == ["SECRETPLANS"]
    assert _one(outcome, "Anti-forensic or wiping tool CCleaner").severity == "high"  # configured and run
    assert _one(outcome, "Anti-forensic or wiping tool BCWipe").technique_id == "T1485"
    assert "2 shares mapped or opened" in _one(outcome, "Network shares used").title
    assert _one(outcome, "E-mail client Outlook in use").technique_id == "T1048"
    drive = _one(outcome, "Cloud sync client Google Drive")
    assert "seen in its sync folder" in drive.title and drive.severity == "medium"
    assert _one(outcome, "Cloud sync client OneDrive").severity == "low"  # ships with Windows 10; only ran
    assert _one(outcome, "Confidential-looking file names on a cloud sync folder").severity == "high"
    profile = _one(outcome, "System profile recorded")
    assert "time zone, last shutdown, computer name; 3 user accounts" in profile.title and profile.severity == "info"
    system = outcome.summary["system"]
    assert system["time_zone"] == "Eastern Standard Time" and system["utc_offset_minutes"] == -240
    assert system["last_shutdown"] == "2012-04-04T01:58:40Z"
    for finding in outcome.findings:
        assert verify_agent_finding(finding, tmp_path, inventory, locate) is None, finding.title
    # Evidence text stays out of titles and recommendations.
    text = json.dumps([[f.title, f.recommendation, f.evidence] for f in outcome.findings])
    for word in ("AA951D0000007252", "SECRETPLANS", "nfury", "controller", "Super Secret"):
        assert word not in text
    rows = [json.loads(line) for line in (tmp_path / "disk" / "pc-00000000-00000000" / da.TIMELINE_FILE)
            .read_text().splitlines()]
    assert rows == sorted(rows, key=lambda row: row["time"]) and len(rows) == outcome.timeline_rows > 100
    assert {"time", "kind", "summary", "source", "locator", "fields"} <= set(rows[0])
    assert any(row["kind"] == "usb_device" and "AA951D0000007252" in row["summary"] for row in rows)


# --------------------------------------------------------------------------
# Verification is real: a changed copy loses its findings
# --------------------------------------------------------------------------


def _ccleaner_finding(tmp_path: Path):
    files = {"Users/cleaner/NTUSER.DAT": ("registry", sample("NTUSER-CCLEANER").read_bytes())}
    outcome, inventory, locate = run_analysis(tmp_path, files)
    finding = _one(outcome, "Anti-forensic or wiping tool CCleaner")
    assert verify_agent_finding(finding, tmp_path, inventory, locate) is None
    key = next(c for c in finding.citations if c.offset)
    return finding, inventory, locate, locate[key.source_file], key


def _flip(path: Path, offset: int) -> None:
    data = bytearray(path.read_bytes())
    data[offset] ^= 0xFF
    path.write_bytes(bytes(data))


def test_tampered_copy_drops_the_finding(tmp_path: Path) -> None:
    finding, inventory, locate, copy, key = _ccleaner_finding(tmp_path)
    _flip(copy, key.offset + 0x50)  # inside the cited registry key: its name
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == \
        "copied file no longer matches its recorded hash"
    kept, dropped = merge_findings([finding], tmp_path, inventory, locate)
    assert kept == [] and dropped == [{"finding_id": finding.finding_id, "worker": "disk_artifacts",
                                       "reason": "copied file no longer matches its recorded hash"}]


def test_change_far_from_the_cited_record_still_drops_the_finding(tmp_path: Path) -> None:
    finding, inventory, locate, copy, _ = _ccleaner_finding(tmp_path)
    _flip(copy, copy.stat().st_size - 1)  # the last byte of the hive, nowhere near the cited cells
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == \
        "copied file no longer matches its recorded hash"


def test_record_reread_is_checked_separately_from_the_file_hash(tmp_path: Path) -> None:
    # Someone who changes the copy and also the recorded file hash is still caught by the record digest.
    finding, inventory, locate, copy, key = _ccleaner_finding(tmp_path)
    _flip(copy, key.offset + 12)  # the cited key's last-write time
    forged = hashlib.sha256(copy.read_bytes()).hexdigest()
    for citation in finding.citations:
        citation.sha256 = forged
    inventory = dict.fromkeys(inventory, forged)
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == \
        "cited record does not match the agent's record"


def test_citation_must_carry_a_matching_recheck_record(tmp_path: Path) -> None:
    finding, inventory, locate, _, key = _ccleaner_finding(tmp_path)
    kept, _ = merge_findings([finding], tmp_path, inventory, locate)
    assert kept[0].verification == "record re-read; copy re-hashed"
    original = list(finding.evidence)
    finding.evidence = [item for item in original if not item.startswith("cite[")]
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == "citation has no re-check record"
    finding.evidence = original
    key.offset += 8  # the citation now points somewhere its re-check record does not
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == \
        "citation does not point where its re-check record does"
    key.offset -= 8
    finding.evidence = [item.replace("regk:", "regk:9") if item.startswith("cite[") else item for item in original]
    assert verify_agent_finding(finding, tmp_path, inventory, locate) is not None
    finding.evidence = original
    del locate[key.source_file]
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == "cited copy is not in the run folder"


def test_file_level_citation_is_labelled_and_still_hash_checked(tmp_path: Path) -> None:
    pytest.importorskip("dissect.util")
    files = {"Windows/Prefetch/ONEDRIVE.EXE-7E152375.pf": ("prefetch", sample("ONEDRIVE.pf").read_bytes())}
    outcome, inventory, locate = run_analysis(tmp_path, files)
    finding = _one(outcome, "Cloud sync client OneDrive")
    assert any(item.startswith("cite[0]=file|") for item in finding.evidence)
    kept, _ = merge_findings([finding], tmp_path, inventory, locate)
    assert kept[0].verification == "file-level: copy re-hashed, no smaller location"
    _flip(next(iter(locate.values())), 100)
    assert verify_agent_finding(finding, tmp_path, inventory, locate) == \
        "copied file no longer matches its recorded hash"


# --------------------------------------------------------------------------
# Hostile input: damaged files become coverage gaps
# --------------------------------------------------------------------------

EXPECTED_ERRORS = (dp.ParseError, struct.error, sqlite3.Error, ValueError, IndexError, KeyError, EOFError,
                   UnicodeError, OverflowError)


@pytest.mark.parametrize(("name", "parser"), [
    ("nero.lnk", dp.parse_lnk), ("auto-win7.jump", dp.parse_automatic_destinations),
    ("custom.jump", dp.parse_custom_destinations), ("PING.pf", dp.parse_prefetch),
    ("TASKHOST.pf", dp.parse_prefetch), ("$II3DF3L.zip", dp.parse_recycle_index),
    ("index.dat", dp.parse_index_dat),
])
def test_mutated_real_files_never_crash_a_parser(tmp_path: Path, name: str, parser) -> None:  # noqa: ANN001
    original = sample(name).read_bytes()
    rng = random.Random(1234)
    target = tmp_path / "mutant"
    for round_number in range(120):
        data = bytearray(original)
        for _ in range(rng.randint(1, 12)):
            position = rng.randrange(len(data))
            data[position:position + rng.choice((1, 2, 4))] = rng.randbytes(rng.choice((1, 2, 4)))
        if round_number % 7 == 0:
            data = data[:rng.randrange(1, len(data))]
        target.write_bytes(bytes(data))
        try:
            records = parser(target)
        except EXPECTED_ERRORS:
            continue
        assert len(records) <= dp.MAX_RECORDS_PER_FILE * 2


def test_mutated_real_hive_never_crashes_the_registry_reader(tmp_path: Path) -> None:
    original = sample("NTUSER-CCLEANER").read_bytes()
    rng = random.Random(99)
    target = tmp_path / "NTUSER.DAT"
    for _ in range(25):
        data = bytearray(original)
        for _ in range(rng.randint(20, 400)):
            position = rng.randrange(4096, len(data))
            data[position:position + 4] = rng.randbytes(4)
        target.write_bytes(bytes(data))
        try:
            records, problems = dr.parse_hive(target, "ntuser")
        except EXPECTED_ERRORS:
            continue
        assert isinstance(records, list) and isinstance(problems, list)


def test_unreadable_copies_become_gaps_not_errors(tmp_path: Path) -> None:
    files = {
        "Windows/System32/config/SYSTEM": ("registry", b"regf" + b"\0" * 60),
        "Windows/System32/config/SECURITY": ("registry", b"regf" + b"\0" * 60),
        "Windows/Prefetch/CALC.EXE-12345678.pf": ("prefetch", b"MAM\x04" + struct.pack("<I", 4096) + b"\xff" * 40),
        f"Users/a/{RECENT}/x.lnk": ("lnk", b"L\0\0\0" + b"\0" * 16),
        "Users/a/AppData/Local/Google/Chrome/User Data/Default/History": ("browser", b"not a database"),
        "$Recycle.Bin/S-1-5-21-1/$IABC.txt": ("recycle_bin", b"\x09" + b"\0" * 40),
        "Windows/System32/winevt/Logs/Security.evtx": ("event_log", b"ElfFile\0"),
    }
    outcome, _, _ = run_analysis(tmp_path, files)
    assert outcome.findings == [] and outcome.files_parsed == 0
    whys = " | ".join(gap["why"] for gap in outcome.gaps)
    for expected in ("registry hive could not be read", "Prefetch file could not be read", "shortcut could not be read",
                     "browser history could not be read", "Recycle Bin index file could not be read",
                     "registry hive this agent does not read"):
        assert expected in whys, expected
    assert "evtx" not in whys  # event logs belong to the core pipeline, not to this agent


# --------------------------------------------------------------------------
# End to end: a disk image holding real artefacts at their Windows paths
# --------------------------------------------------------------------------


def _real_windows_tree() -> dict:
    """Real artefacts placed where Windows keeps them, plus two hand-built shortcuts to a USB stick."""
    recent = {
        "NeroInfoTool.lnk": sample("nero.lnk").read_bytes(),
        "example.lnk": sample("example.lnk").read_bytes(),
        # Hand-built: E: is the USB stick in the real SYSTEM hive's MountedDevices.
        "pricing.lnk": make_lnk(f"E:\\{CANARY}\\secret_pricing.xlsx", serial=0xB84479ED, label="SECRETPLANS"),
        "AutomaticDestinations": {"1b4dd67f29cb1962.automaticDestinations-ms": sample("auto-win7.jump").read_bytes()},
        "CustomDestinations": {"5afe4de1b92fc382.customDestinations-ms": sample("custom.jump").read_bytes()},
    }
    return {
        "Windows": {
            "System32": {"config": {"SYSTEM": sample("SYSTEM").read_bytes(), "SOFTWARE": sample("SOFTWARE").read_bytes(),
                                    "SAM": sample("SAM").read_bytes()}},
            "Prefetch": {"PING.EXE-B29F6629.pf": sample("PING.pf").read_bytes(),
                         "ONEDRIVE.EXE-7E152375.pf": sample("ONEDRIVE.pf").read_bytes()},
            "inf": {"setupapi.dev.log": sample("setupapi.dev.log").read_bytes()},
        },
        "Users": {
            "nfury": {
                "NTUSER.DAT": sample("NTUSER-WIN7").read_bytes(),
                "AppData": {
                    "Roaming": {"Microsoft": {"Windows": {"Recent": recent}},
                                "Mozilla": {"Firefox": {"Profiles": {"x.default": {
                                    "places.sqlite": sample("firefox118-places").read_bytes()}}}}},
                    "Local": {"Google": {"Chrome": {"User Data": {"Default": {
                        "History": sample("chrome-History").read_bytes()}}},
                        "Drive": {"user_default": {"snapshot.db": sample("gdrive-snapshot.db").read_bytes()}}}},
                },
            },
            "cleaner": {"NTUSER.DAT": sample("NTUSER-CCLEANER").read_bytes()},
        },
        "$Recycle.Bin": {"S-1-5-21-100689374-1717798114-2601648136-1000": {
            "$II3DF3L.zip": sample("$II3DF3L.zip").read_bytes(), "$I103S5F.jpg": sample("$I103S5F.jpg").read_bytes()}},
    }


def test_autopilot_on_an_image_of_real_artefacts(tmp_path: Path) -> None:
    pytest.importorskip("dissect.target")
    pytest.importorskip("dissect.fat")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    build_fat_image(evidence / "pc.dd", _real_windows_tree(), size_mb=72)
    before = hashlib.sha256((evidence / "pc.dd").read_bytes()).hexdigest()
    plan = {p.name: p for p in plan_agents(profile_evidence(evidence), agents_module.agent_availability())}
    assert plan["disk_artifacts"].run and plan["disk_image"].run

    run = tmp_path / "run"
    draft = start(input_dir=evidence, output_dir=run, case_id="real", llm="off")

    assert hashlib.sha256((evidence / "pc.dd").read_bytes()).hexdigest() == before
    agents = {a["name"]: a for a in draft["agents"]}
    assert agents["disk_artifacts"]["status"] == "ok", agents["disk_artifacts"]["detail"]
    assert agents["disk_image"]["status"] == "ok", agents["disk_image"]["detail"]
    assert not any(d["worker"] == "disk_artifacts" for d in draft["dropped"]), draft["dropped"]
    assert not any("same name as an evidence file" in gap["why"] for gap in draft["coverage_gaps"])
    assert sum("members_extracted" in a["notes"] for a in agents.values()) == 1  # the copies are listed once

    found = [f for f in draft["findings"] if f["worker"] == "disk_artifacts"]
    titles = [f["title"] for f in found]

    def one(start_of_title: str) -> dict:
        matches = [f for f in found if f["title"].startswith(start_of_title)]
        assert len(matches) == 1, (start_of_title, titles)
        return matches[0]

    usb = one("USB storage device connected (device 1 of 1)")
    assert usb["severity"] == "low" and usb["technique_id"] == "T1052.001"
    assert usb["verification"] == "record re-read; copy re-hashed"
    assert {c["source_file"] for c in usb["citations"]} <= {
        "pc.dd!/C:/Windows/System32/config/SYSTEM", "pc.dd!/C:/Windows/System32/config/SOFTWARE"}
    removable = one("Files or folders opened on removable media")
    assert removable["severity"] == "medium" and "1 path on one volume" in removable["title"]
    assert one("Confidential-looking file names on removable media")["severity"] == "high"
    assert one("Anti-forensic or wiping tool CCleaner")["severity"] == "high"
    assert one("Anti-forensic or wiping tool BCWipe")["tactic"] == "impact"
    assert one("Cloud sync client Google Drive")["technique_id"] == "T1567.002"
    assert one("E-mail client Outlook in use")["severity"] == "low"
    assert "2 deleted items" in one("Items in the Recycle Bin")["title"]
    assert one("Network shares used")["technique_id"] == "T1039"
    profile = one("System profile recorded")
    assert "time zone, install date, last shutdown, computer name; 3 user accounts" in profile["title"]
    assert one("Cloud sync client OneDrive")["verification"] == "file-level: copy re-hashed, no smaller location"
    assert 10 <= len(found) <= 40  # aggregated: tens of findings, not one per record

    # Evidence text never reaches the draft.
    text = (run / DRAFT_JSON).read_text() + (run / DRAFT_MD).read_text()
    for word in (CANARY, "AA951D0000007252", "SECRETPLANS", "funny cats", "StarFury"):
        assert word not in text, word

    members = json.loads((run / "disk" / "disk_images.json").read_text())
    folder = run / "disk" / members[0]["folder"]
    summary = json.loads((folder / "disk_summary.json").read_text())
    # Every key the disk-image agent wrote is still there; this agent added exactly one.
    assert {"image", "image_sha256", "segments", "reader", "disks", "volumes", "files_copied", "bytes_copied",
            "properties", "plugins", "user_folders", "listing"} <= set(summary)
    assert summary["properties"]["hostname"] == "WKS-WIN732BITA"  # dissect read the real hives too
    assert summary["plugins"]["users"]["status"] == "ok" and summary["plugins"]["usb"]["rows"]
    artifacts = summary["artifacts"]
    assert artifacts["usb_devices"][0]["serial"] == "AA951D0000007252"
    assert artifacts["usb_devices"][0]["volume_serials"] == ["B844-79ED"]
    assert artifacts["system"]["os_install_date"] == "2010-11-10T16:28:55Z"
    assert artifacts["system"]["computer_name"] == "WKS-WIN732BITA"
    assert {tool["program"] for tool in artifacts["anti_forensic_tools"]} == {"BCWipe", "CCleaner"}
    assert set(artifacts["findings"]) == {f["finding_id"] for f in found}
    detail = artifacts["findings"][removable["finding_id"]]
    assert detail["files"][0]["path"] == f"E:\\{CANARY}\\secret_pricing.xlsx" and detail["volume"] == "B844-79ED"

    rows = [json.loads(line) for line in (folder / "artifact_timeline.jsonl").read_text().splitlines()]
    assert len(rows) == artifacts["timeline_rows"] > 300
    assert [row["time"] for row in rows] == sorted(row["time"] for row in rows)
    kinds = {row["kind"] for row in rows}
    assert {"usb_device", "lnk", "jump_list", "prefetch", "recycle_bin", "browser_visit", "web_search", "user_assist",
            "office_mru", "cloud_file", "installed_program", "system_fact"} <= kinds
    assert any(row["kind"] == "recycle_bin" and "StarFury.zip" in row["summary"] for row in rows)

    # The CFReDS checklist reads the same three outputs.
    import importlib.util

    spec = importlib.util.spec_from_file_location("cfreds_score", Path(__file__).resolve().parents[1] / "lab"
                                                  / "cfreds_score.py")
    scorer = importlib.util.module_from_spec(spec)
    sys.modules["cfreds_score"] = scorer
    spec.loader.exec_module(scorer)
    results = {r["theme"]: r for r in scorer.score(scorer.load_run(run))}
    assert len(results) >= 25
    for theme in ("USB storage device(s) identified with a serial number", "Time zone of the computer",
                  "Operating system install date", "User accounts listed", "Files opened from removable media",
                  "Anti-forensic tool found: CCleaner", "Cloud storage client found: Google Drive",
                  "Recycle Bin deletions", "E-mail client artefacts (Outlook profile or mailbox file)",
                  "Network drive / shared folder used", "Timeline of dated artefacts written"):
        assert results[theme]["found"], theme
    for theme in ("Anti-forensic tool found: Eraser", "Both USB sticks found (the scenario has two)",
                  "Browser history deletion noticed"):
        assert not results[theme]["found"], theme  # not in this image, and the checklist says so
    assert scorer.main(["--run-dir", str(run), "--json", str(tmp_path / "score.json")]) == 0
    assert json.loads((tmp_path / "score.json").read_text())["total"] == len(results)


def test_artifacts_agent_alone_still_gets_its_citations_verified(tmp_path: Path) -> None:
    pytest.importorskip("dissect.target")
    pytest.importorskip("dissect.fat")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    tree = {"Windows": {"System32": {"config": {"SAM": sample("SAM").read_bytes()}}},
            "Users": {"cleaner": {"NTUSER.DAT": sample("NTUSER-CCLEANER").read_bytes()}}}
    build_fat_image(evidence / "pc.dd", tree, size_mb=6)
    draft = start(input_dir=evidence, output_dir=tmp_path / "run", case_id="solo", llm="off",
                  only_agents=["disk_artifacts"])
    (agent,) = [a for a in draft["agents"] if a["name"] == "disk_artifacts"]
    assert agent["status"] == "ok" and agent["notes"]["members_extracted"] == 2
    titles = [f["title"] for f in draft["findings"]]
    assert any(title.startswith("Anti-forensic or wiping tool CCleaner") for title in titles)
    assert draft["dropped"] == []
    assert all(f["verification"] == "record re-read; copy re-hashed" for f in draft["findings"])


def test_copy_changed_between_analysis_and_coordination_is_dropped(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    pytest.importorskip("dissect.target")
    pytest.importorskip("dissect.fat")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    tree = {"Windows": {"System32": {"config": {"SAM": sample("SAM").read_bytes()}}},
            "Users": {"cleaner": {"NTUSER.DAT": sample("NTUSER-CCLEANER").read_bytes()}}}
    build_fat_image(evidence / "pc.dd", tree, size_mb=6)
    real_run = agents_module.DiskArtifactsAgent.run

    def run_then_tamper(self, ctx, store, tools):  # noqa: ANN001
        result = real_run(self, ctx, store, tools)
        (copy,) = (ctx.run_dir / "disk").glob("*/files/C/Users/cleaner/NTUSER.DAT")
        _flip(copy, 5000)
        return result

    monkeypatch.setattr(agents_module.DiskArtifactsAgent, "run", run_then_tamper)
    draft = start(input_dir=evidence, output_dir=tmp_path / "run", case_id="tamper", llm="off",
                  only_agents=["disk_artifacts"])
    reasons = {d["reason"] for d in draft["dropped"] if d["worker"] == "disk_artifacts"}
    assert reasons == {"copied file no longer matches its recorded hash"}
    kept = [f for f in draft["findings"] if f["worker"] == "disk_artifacts"]
    assert kept and all("NTUSER.DAT" not in c["source_file"] for f in kept for c in f["citations"])
    assert not any(f["title"].startswith("Anti-forensic") for f in kept)


def test_parsers_never_import_dissect_at_import_time() -> None:
    for module in (dp, dr, da):
        assert "dissect" not in module.__dict__
