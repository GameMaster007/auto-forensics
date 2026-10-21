"""Re-read each cited row and decide whether it supports the claim.

The citation check only proves the pointer was ingested. This pass
opens the file again, checks the hash, and reads the cited row or
byte window. A claim sentence has to appear in that text. A judge may
reject a claim the rules accepted. It cannot restore a claim the rules
rejected.

Reasons are fixed phrases. The cited text is not copied into the
verdict, so an instruction hidden in the evidence does not become
part of the record.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from .models import ArtifactEvent, Citation, Finding
from .security import sha256_file, stays_in_tree

MAX_VERIFY_BYTES = 8 * 1024 * 1024
# Same window ``analyze_binary`` uses for string hits. An offset-0
# citation has to see a keyword found in that window.
MAX_BINARY_VERIFY_BYTES = 32 * 1024 * 1024
_OFFSET_WINDOW = 8192
_TEXT_PARSERS = {
    "json-artifact-parser",
    "csv-artifact-parser",
    "text-artifact-parser",
}

_METADATA_PREFIXES = (
    "suspicious_score=",
    "sha256=",
    "source=",
    "artifact_id=",
    "event_type=",
    "file=",
    "rule_file=",
    "tags=",
    "rule=",
    "matched_events=",
)
_BOILERPLATE = {
    "LLM-generated draft. Analyst verification required.",
}

REASON_SUPPORTED = "cited row contains every claim sentence"
REASON_UNSUPPORTED = "cited row does not contain a claim sentence"
REASON_HASH = "cited file hash does not match"
REASON_UNREADABLE = "cited row could not be read"
REASON_NO_CLAIM = "no grounded claim sentence"
REASON_DETECTOR = "detector label; cited file hash matches"
REASON_SCORE = "score-based; cited file hash matches"
REASON_JUDGE = "judge rejected the claim"
REASON_NEEDS_REVIEW = "cited row is over the judge cap; rules supported it"


class ClaimJudge(Protocol):
    """Optional second opinion. ``cited_text`` is quoted data."""

    name: str

    def judge(self, claim: str, cited_text: str) -> str | None:
        """Return ``supported``, ``rejected``, or ``None`` if no opinion."""


@dataclass(slots=True)
class ClaimVerdict:
    """One verifier decision for one finding."""

    finding_id: str
    verdict: str
    reason: str
    judge: str
    artifact_id: str
    source_file: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


class MockClaimJudge:
    """Offline judge. It checks the same substring the rules use.

    It does not read the cited text as instructions. A phrase such as
    "ignore previous instructions" does not change the decision.
    """

    name = "mock"

    def judge(self, claim: str, cited_text: str) -> str:
        if _norm(claim) in _norm(cited_text):
            return "supported"
        return "rejected"


def resolve_verifier_mode(provider: str, explicit: str | None) -> str:
    """Pick rules, mock, or llm from the run's provider."""
    if explicit in {"rules", "mock", "llm"}:
        return explicit
    if provider == "mock":
        return "mock"
    if provider in {"ollama", "openai_compatible"}:
        return "llm"
    return "rules"


def verifier_limit_name(mode: str) -> str:
    """Value stored in ``limits.verifier``."""
    if mode == "mock":
        return "rules+mock"
    if mode == "llm":
        return "rules+llm"
    return "rules"


def verify_findings(
    findings: list[Finding],
    input_dir: Path,
    judge: ClaimJudge | None = None,
) -> tuple[list[Finding], list[ClaimVerdict]]:
    """Return supported findings and a verdict for every finding.

    Unsupported findings are omitted from the kept list. Their verdicts
    stay in the second list.
    """
    kept: list[Finding] = []
    verdicts: list[ClaimVerdict] = []
    for finding in findings:
        verdict = _verify_one(finding, input_dir, judge)
        verdicts.append(verdict)
        if verdict.verdict == "supported":
            finding.verification = "score-based" if verdict.reason == REASON_SCORE else "supported"
            kept.append(finding)
        elif verdict.verdict == "needs review":
            finding.verification = "needs review"
            kept.append(finding)
    return kept, verdicts


def _verify_one(finding: Finding, input_dir: Path, judge: ClaimJudge | None) -> ClaimVerdict:
    texts: list[str] = []
    first = finding.citations[0] if finding.citations else None
    for citation in finding.citations:
        text, error = read_cited_text(input_dir, citation)
        if error:
            return _verdict(finding, "rejected", error, "rules", citation)
        texts.append(text or "")

    cited = "\n".join(texts)
    lines = claim_lines(finding)
    if not lines:
        if texts and finding.origin == "detector":
            return _verdict(finding, "supported", REASON_DETECTOR, "rules", first)
        if texts and finding.origin in {"heuristic", "llm"}:
            return _verdict(finding, "supported", REASON_SCORE, "rules", first)
        return _verdict(finding, "rejected", REASON_NO_CLAIM, "rules", first)

    if any(_norm(line) not in _norm(cited) for line in lines):
        return _verdict(finding, "rejected", REASON_UNSUPPORTED, "rules", first)

    if judge is not None:
        used_judge = False
        needs_review = False
        for line in lines:
            decision = judge.judge(line, cited)
            if decision is None:
                used_judge = False
                break
            used_judge = True
            if decision == "rejected":
                return _verdict(finding, "rejected", REASON_JUDGE, judge.name, first)
            if decision == "needs_review":
                needs_review = True
        if used_judge and needs_review:
            return _verdict(finding, "needs review", REASON_NEEDS_REVIEW, judge.name, first)
        if used_judge:
            return _verdict(finding, "supported", REASON_SUPPORTED, judge.name, first)
    return _verdict(finding, "supported", REASON_SUPPORTED, "rules", first)


def claim_lines(finding: Finding) -> list[str]:
    """Evidence lines that assert something about the cited row.

    Scores, hashes, and the fixed draft notice are not claims. The
    title is a label, not a sentence that has to appear in the row.
    """
    lines: list[str] = []
    for raw in finding.evidence:
        text = raw.strip()
        if not text or text in _BOILERPLATE:
            continue
        if any(text.startswith(prefix) for prefix in _METADATA_PREFIXES):
            continue
        lines.append(text)
    return lines


def read_cited_text(input_dir: Path, citation: Citation) -> tuple[str | None, str]:
    """Re-hash the cited file and return the cited row or byte window."""
    path = locate_source(input_dir, citation.source_file, citation.sha256)
    if path is None:
        return None, REASON_UNREADABLE
    if sha256_file(path).lower() != citation.sha256.lower():
        return None, REASON_HASH
    if citation.row is not None:
        structured = _read_structured_record(path, citation.row)
        if structured is not None:
            return structured, ""
        if _is_structured_artifact(path):
            return None, REASON_UNREADABLE
        if path.stat().st_size > MAX_VERIFY_BYTES:
            return None, REASON_UNREADABLE
        text = _read_row(path, citation.row)
        if text is None:
            return None, REASON_UNREADABLE
        return text, ""
    start = citation.offset if citation.offset is not None else 0
    if start < 0:
        return None, REASON_UNREADABLE
    with path.open("rb") as handle:
        if start:
            handle.seek(start)
        cap = _OFFSET_WINDOW if start else min(path.stat().st_size, MAX_BINARY_VERIFY_BYTES)
        window = handle.read(cap)
    if start and not window and start >= path.stat().st_size:
        return None, REASON_UNREADABLE
    return window.decode("utf-8", errors="replace"), ""


def locate_source(input_dir: Path, source_file: str, sha256: str = "") -> Path | None:
    """Find ``source_file`` under ``input_dir``.

    A relative path is tried first. A bare file name is accepted when
    exactly one file under the directory has that name. When several
    files share the name, the citation hash picks the file.
    """
    root = input_dir.resolve()
    rel = Path(source_file)
    if rel.is_absolute() or ".." in rel.parts or not source_file:
        return None
    direct = (root / rel).resolve()
    if direct.is_file() and not direct.is_symlink() and direct.is_relative_to(root):
        return direct
    matches = [
        path
        for path in sorted(root.rglob("*"))
        if path.name == rel.name and stays_in_tree(path, root) and len(path.relative_to(root).parts) <= 20
    ]
    if len(matches) == 1:
        return matches[0]
    wanted = sha256.lower()
    if wanted:
        for path in matches:
            if sha256_file(path).lower() == wanted:
                return path
    return None


def _read_row(path: Path, row: int) -> str | None:
    if row < 1:
        return None
    if path.suffix.lower() == ".json":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raw = None
        if isinstance(raw, list):
            records = [item for item in raw if isinstance(item, dict)]
            if row <= len(records):
                return _json_record_text(records[row - 1])
        elif isinstance(raw, dict) and row == 1:
            return _json_record_text(raw)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if row <= len(lines):
        return lines[row - 1]
    return None


def _is_structured_artifact(path: Path) -> bool:
    """True when the file is parsed into records that are not text lines."""
    from .plugins import ArtifactParserRegistry

    registry = ArtifactParserRegistry()
    registry.register_defaults()
    parser = registry.parser_for_path(path)
    return parser is not None and parser.name not in _TEXT_PARSERS


def _read_structured_record(path: Path, row: int) -> str | None:
    """Re-parse one EVTX, pcap, registry, prefetch, MFT, or memory record.

    Those parsers stamp a synthetic row. The description is not a line
    in the file, so the cited text is the parsed record.
    """
    if not _is_structured_artifact(path):
        return None
    from .plugins import ArtifactParserRegistry

    registry = ArtifactParserRegistry()
    registry.register_defaults()
    events = registry.parse(path)
    for index, event in enumerate(events, start=1):
        recorded = event.metadata.get("row")
        record_row = recorded if isinstance(recorded, int) and recorded >= 1 else index
        if record_row == row:
            return _event_text(event)
    return None


def _event_text(event: ArtifactEvent) -> str:
    parts = [event.description]
    for key, value in event.metadata.items():
        if key in {"source_file", "source_sha256", "row", "offset"}:
            continue
        if value is None:
            continue
        parts.append(f"{key}={value}")
    return "\n".join(parts)


def _json_record_text(record: dict) -> str:
    """Field values plus a UTF-8 dump.

    ``json.dumps`` escapes quotes and, with ``ensure_ascii``, non-ASCII.
    The claim sentence is the field value, so those values are included
    as themselves.
    """
    values: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, str):
            values.append(node)
        elif isinstance(node, dict):
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(record)
    dumped = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return dumped + "\n" + "\n".join(values)


def _verdict(
    finding: Finding,
    verdict: str,
    reason: str,
    judge: str,
    citation: Citation | None,
) -> ClaimVerdict:
    return ClaimVerdict(
        finding_id=finding.finding_id,
        verdict=verdict,
        reason=reason,
        judge=judge,
        artifact_id=citation.artifact_id if citation else "",
        source_file=citation.source_file if citation else "",
    )


def _norm(value: str) -> str:
    return " ".join(value.lower().split())
