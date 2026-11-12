"""Score an autopilot run of the NIST CFReDS "Data Leakage" case against the themes of its published answers.

The case: an employee copies confidential files to USB sticks and a CD,
uses a network drive, a cloud sync client and e-mail, searches for how to
leak data and hide it, then runs anti-forensic tools. This script reads a
run folder (draft or signed) and prints one line per theme: FOUND or
MISSED, and what matched.

    auto-forensics-autopilot start --input-dir /cases/cfreds --output-dir /cases/run-01 --case-id cfreds
    python lab/cfreds_score.py --run-dir /cases/run-01

It reads only three things from the run: the findings in
``autopilot_draft.json``, each image's ``disk_summary.json`` (the
``artifacts`` key and dissect's ``properties``/``plugins``), and each
image's ``artifact_timeline.jsonl``. It does not need the answer PDF: the
checks below are the scenario's themes in plain words, matched by finding
rule, ATT&CK technique or keyword. A FOUND line means the run surfaced
that theme, not that every detail in the answer key is right; read the
matched text and compare it with the answers yourself.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(slots=True)
class Run:
    """Everything the checks look at, merged over all disk images in the run."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    details: dict[str, dict[str, Any]] = field(default_factory=dict)  # finding id -> detail from disk_summary
    artifacts: list[dict[str, Any]] = field(default_factory=list)  # one "artifacts" block per image
    summaries: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)

    # -- helpers the checks use ---------------------------------------------

    def rule(self, prefix: str) -> list[dict[str, Any]]:
        """Findings whose detection rule starts with ``prefix`` (rules are recorded in disk_summary.json)."""
        ids = {fid for fid, detail in self.details.items() if str(detail.get("rule", "")).startswith(prefix)}
        return [f for f in self.findings if f.get("finding_id") in ids]

    def titled(self, pattern: str) -> list[dict[str, Any]]:
        rx = re.compile(pattern, re.IGNORECASE)
        return [f for f in self.findings if rx.search(str(f.get("title", "")))]

    def technique(self, technique_id: str) -> list[dict[str, Any]]:
        return [f for f in self.findings if str(f.get("technique_id", "")).startswith(technique_id)]

    def rows(self, kind: str, pattern: str = "") -> list[dict[str, Any]]:
        rx = re.compile(pattern, re.IGNORECASE) if pattern else None
        return [row for row in self.timeline if row.get("kind") == kind
                and (rx is None or rx.search(str(row.get("summary", ""))))]

    def each(self, key: str) -> list[Any]:
        """Items of a list-valued ``artifacts`` key from every image."""
        out: list[Any] = []
        for block in self.artifacts:
            value = block.get(key)
            if isinstance(value, list):
                out.extend(value)
        return out

    def system(self, key: str) -> Any:
        for block in self.artifacts:
            value = (block.get("system") or {}).get(key)
            if value:
                return value
        return None

    def dissect(self, name: str) -> Any:
        for summary in self.summaries:
            value = (summary.get("properties") or {}).get(name)
            if value:
                return value
        return None

    def detail_text(self, findings: list[dict[str, Any]]) -> str:
        return json.dumps([self.details.get(f.get("finding_id"), {}) for f in findings])


def load_run(run_dir: Path) -> Run:
    run = Run()
    draft_path = run_dir / "autopilot_draft.json"
    if not draft_path.is_file():
        raise SystemExit(f"{draft_path} not found: is this an autopilot run folder?")
    draft = json.loads(draft_path.read_text(encoding="utf-8"))
    run.findings = [f for f in draft.get("findings", []) if isinstance(f, dict)]
    for summary_path in sorted((run_dir / "disk").glob("*/disk_summary.json")):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        run.summaries.append(summary)
        artifacts = summary.get("artifacts")
        if isinstance(artifacts, dict):
            run.artifacts.append(artifacts)
            run.details.update({k: v for k, v in (artifacts.get("findings") or {}).items() if isinstance(v, dict)})
        timeline = summary_path.with_name("artifact_timeline.jsonl")
        if timeline.is_file():
            with timeline.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, dict):
                        run.timeline.append(row)
    return run


def _first(items: list[dict[str, Any]], key: str = "title") -> str:
    return str(items[0].get(key, ""))[:110] if items else ""


def _names(items: list[Any], key: str) -> str:
    return ", ".join(sorted({str(item.get(key)) for item in items if isinstance(item, dict) and item.get(key)}))[:110]


Check = Callable[[Run], str]  # returns what matched, or "" when the theme was missed


def _usb_with_serial(run: Run) -> str:
    devices = [d for d in run.each("usb_devices") if d.get("serial") and d.get("serial_is_unique", True)]
    return f"{len(devices)} device(s): {_names(devices, 'serial')}" if devices else ""


def _two_usb(run: Run) -> str:
    devices = [d for d in run.each("usb_devices") if d.get("serial")]
    return f"{len(devices)} devices" if len(devices) >= 2 else ""


def _usb_times(run: Run) -> str:
    devices = [d for d in run.each("usb_devices") if d.get("first_seen") or d.get("first_install_local")]
    return f"first seen {devices[0].get('first_seen') or devices[0].get('first_install_local')}" if devices else ""


def _usb_volume(run: Run) -> str:
    devices = [d for d in run.each("usb_devices") if d.get("volume_names") or d.get("drive_letters")
               or d.get("volume_serials")]
    if not devices:
        return ""
    return f"letters {devices[0].get('drive_letters')}, names {devices[0].get('volume_names')}"


def _program(category: str, pattern: str, need_run: bool = False) -> Check:
    def check(run: Run) -> str:
        rx = re.compile(pattern, re.IGNORECASE)
        tools = [t for t in run.each(category) if rx.search(str(t.get("program", "")))]
        if need_run:
            tools = [t for t in tools if int(t.get("run_count") or 0) > 0]
        if tools:
            return f"{tools[0].get('program')}: {tools[0].get('evidence')}"
        # dissect's own list of installed programs is a second source.
        for summary in run.summaries:
            rows = ((summary.get("plugins") or {}).get("applications") or {}).get("rows") or []
            hit = next((row for row in rows if rx.search(str(row.get("name", "")))), None)
            if hit and not need_run:
                return f"installed program list: {hit.get('name')}"
        return ""
    return check


def _google_drive_use(run: Run) -> str:
    files = run.rows("cloud_file")
    if files:
        return f"{len(files)} file(s) in the sync database"
    for tool in run.each("cloud_clients"):
        if "google" in str(tool.get("program", "")).lower() and (tool.get("run_count") or tool.get(
                "files_in_sync_folder")):
            return f"client run {tool.get('run_count')} time(s), {tool.get('files_in_sync_folder')} sync-folder file(s)"
    visits = run.rows("browser_visit", r"drive\.google\.com|docs\.google\.com")
    return f"{len(visits)} visit(s) to Google Drive" if visits else ""


def _web(category: str) -> Check:
    def check(run: Run) -> str:
        for block in run.artifacts:
            entry = (block.get("web_categories") or {}).get(category)
            if entry:
                return f"{entry.get('visits')} visit(s): {', '.join(list(entry.get('sites', {}))[:4])}"
        return ""
    return check


def _search(theme: str, pattern: str) -> Check:
    def check(run: Run) -> str:
        rx = re.compile(pattern, re.IGNORECASE)
        hits = [s for s in run.each("flagged_searches") if theme in (s.get("themes") or []) or rx.search(
            str(s.get("term", "")))]
        if hits:
            return f"{len(hits)} search(es), e.g. {str(hits[0].get('term'))[:70]!r}"
        rows = run.rows("web_search", pattern)
        return f"{len(rows)} search(es) in the timeline" if rows else ""
    return check


def _accounts(run: Run) -> str:
    accounts = run.system("user_accounts") or []
    if accounts:
        return f"{len(accounts)} account(s): {_names(accounts, 'name')}"
    for summary in run.summaries:
        rows = ((summary.get("plugins") or {}).get("users") or {}).get("rows") or []
        if rows:
            return f"{len(rows)} user(s) from dissect: {_names(rows, 'name')}"
    return ""


def _installed(run: Run) -> str:
    rows = run.rows("installed_program")
    if rows:
        return f"{len(rows)} install record(s) in the timeline"
    for summary in run.summaries:
        listed = ((summary.get("plugins") or {}).get("applications") or {}).get("rows") or []
        if listed:
            return f"{len(listed)} program(s) from dissect"
    return ""


def _network_share(run: Run) -> str:
    shares = run.each("network_shares")
    return f"{len(shares)} share(s): {_names(shares, 'share')}" if shares else ""


def _mail(run: Run) -> str:
    clients = run.each("email_clients")
    stores = run.rows("mail_store") + run.rows("mail_profile")
    if clients or stores:
        return f"{_names(clients, 'program') or 'mail profile'}; {len(stores)} profile/store record(s)"
    return ""


def _history_deleted(run: Run) -> str:
    return _first(run.rule("history-")) or _first(run.titled(r"history (was cleared|rows are missing)"))


def _time_zone(run: Run) -> str:
    return str(run.system("time_zone") or run.dissect("timezone") or "")


def _burning(run: Run) -> str:
    return _first(run.rule("disc-burn")) or _first(run.titled(r"CD/DVD|burning")) or (
        f"{len(run.rows('cd_burning'))} CD burning registry record(s)" if run.rows("cd_burning") else "")


# (what the scenario says in plain words, how the run is checked)
CHECKS: tuple[tuple[str, Check], ...] = (
    ("Computer identified (name, Windows version)",
     lambda run: " / ".join(filter(None, [str(run.system("computer_name") or run.dissect("hostname") or ""),
                                          str(run.system("os_version") or run.dissect("version") or "")]))),
    ("Operating system install date", lambda run: str(run.system("os_install_date") or run.dissect("install_date") or "")),
    ("Time zone of the computer", _time_zone),
    ("Last shutdown time", lambda run: str(run.system("last_shutdown") or "")),
    ("User accounts listed", _accounts),
    ("Installed programs listed", _installed),
    ("USB storage device(s) identified with a serial number", _usb_with_serial),
    ("Both USB sticks found (the scenario has two)", _two_usb),
    ("USB first-connection time", _usb_times),
    ("USB stick linked to a drive letter or volume name", _usb_volume),
    ("Files opened from removable media", lambda run: _first(run.rule("files-on-removable"))),
    ("Many files touched on removable media in a short time", lambda run: _first(run.rule("external-burst"))),
    ("Confidential file names on external media, a cloud folder or the burn folder",
     lambda run: _first(run.rule("confidential-names"))),
    ("Network drive / shared folder used", _network_share),
    ("Files opened from the network share", lambda run: _first(run.rule("files-on-network"))),
    ("Cloud storage client found: Google Drive", _program("cloud_clients", r"google drive")),
    ("Cloud storage client found: iCloud", _program("cloud_clients", r"icloud")),
    ("Google Drive actually used (synced files, client run, or site visits)", _google_drive_use),
    ("Cloud storage web sites visited", _web("cloud_storage")),
    ("E-mail client artefacts (Outlook profile or mailbox file)", _mail),
    ("Anti-forensic tool found: CCleaner", _program("anti_forensic_tools", r"ccleaner")),
    ("Anti-forensic tool found: Eraser", _program("anti_forensic_tools", r"eraser")),
    ("An anti-forensic tool was run (run count from Prefetch or UserAssist)",
     _program("anti_forensic_tools", r".", need_run=True)),
    ("CD/DVD burning traces", _burning),
    ("Files opened from a CD/DVD or staged for burning",
     lambda run: _first(run.rule("files-on-optical")) or _first(run.rule("disc-burn-staging"))),
    ("Recycle Bin deletions", lambda run: _first(run.rule("recycle-bin")) or _first(run.technique("T1070.004"))),
    ("Searches about leaking information", _search("data_leak", r"leak|confidential|intellectual property")),
    ("Searches about anti-forensics or deleting data",
     _search("anti_forensics", r"anti.?forensic|eraser|ccleaner|delete|wipe")),
    ("Searches about cloud storage or forensic investigation",
     lambda run: _search("cloud_storage", r"cloud|google drive|icloud")(run)
     or _search("forensic_awareness", r"forensic|investigation|event log")(run)),
    ("Web browsing history recovered", lambda run: (lambda n: f"{n} visit(s)" if n else "")(len(run.rows("browser_visit")))),
    ("Browser history deletion noticed", _history_deleted),
    ("Program runs recovered (Prefetch / UserAssist)",
     lambda run: (lambda n: f"{n} run record(s)" if n else "")(len(run.rows("prefetch")) + len(run.rows("user_assist")))),
    ("Timeline of dated artefacts written",
     lambda run: f"{len(run.timeline)} row(s), {run.timeline[0].get('time')} to {run.timeline[-1].get('time')}"
     if len(run.timeline) >= 50 else ""),
)


def score(run: Run) -> list[dict[str, Any]]:
    results = []
    for theme, check in CHECKS:
        try:
            matched = check(run)
        except Exception as exc:  # noqa: BLE001 - a malformed run file must not stop the other checks
            matched = ""
            theme = f"{theme} [check failed: {type(exc).__name__}]"
        results.append({"theme": theme, "found": bool(matched), "matched": str(matched)[:160]})
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run-dir", type=Path, required=True, help="autopilot run folder (draft or signed)")
    parser.add_argument("--json", type=Path, default=None, help="also write the results to this file")
    args = parser.parse_args(argv)
    run = load_run(args.run_dir.resolve())
    results = score(run)
    found = sum(1 for result in results if result["found"])
    signed = (args.run_dir / "signature.json").is_file()
    print(f"CFReDS data-leakage checklist for {args.run_dir} ({'signed' if signed else 'draft'} run)")
    print(f"{len(run.findings)} finding(s), {len(run.summaries)} disk image(s), {len(run.timeline)} timeline row(s)")
    print()
    for number, result in enumerate(results, start=1):
        mark = "FOUND " if result["found"] else "MISSED"
        print(f"{number:2}. {mark} {result['theme']}")
        if result["found"]:
            print(f"           {result['matched']}")
    print()
    print(f"Total: {found} of {len(results)} themes found")
    if not run.artifacts:
        print("No disk artefact summary in this run: was a disk image present and the 'disk' extra installed?")
    if args.json:
        args.json.write_text(json.dumps({"found": found, "total": len(results), "signed": signed,
                                         "results": results}, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
