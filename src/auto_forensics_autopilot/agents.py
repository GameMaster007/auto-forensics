"""Specialist agents that run in parallel during an autopilot run.

Each agent is a worker in the core sense: it submits findings to one
shared ``CaseStore`` and calls tools only through its own
``ToolRegistry``, so every call lands in the tool log.

Rules every agent follows:

* Read evidence read-only and bounded by size.
* Cite every finding with the file's SHA-256 and a 1-based row.
* Never copy evidence text into a finding. A finding names the rule
  that matched and stores a SHA-256 of the matched line, so the
  coordinator can verify the row without quoting it.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from auto_forensics.case_store import CaseStore
from auto_forensics.models import Citation, Finding
from auto_forensics.pipeline import PipelineConfig, run_case
from auto_forensics.security import sha256_file
from auto_forensics.tools import ToolRegistry

from .triage import EvidenceProfile

MAX_SCAN_BYTES = 8 * 1024 * 1024
MAX_LINE_CHARS = 16 * 1024
MAX_FINDINGS_PER_FILE = 25


@dataclass(slots=True)
class AgentContext:
    case_id: str
    input_dir: Path
    run_dir: Path
    profile: EvidenceProfile
    llm: str = "mock"
    llama_endpoint: str = "http://localhost:11434"
    llama_model: str = "llama3.1:8b"
    rules_dir: Path | None = None


@dataclass(slots=True)
class AgentResult:
    name: str
    status: str = "ok"
    detail: str = ""
    finding_count: int = 0
    notes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "finding_count": self.finding_count,
            "notes": self.notes,
        }


def line_digest(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8", errors="surrogatepass")).hexdigest()


def stable_id(prefix: str, *parts: object) -> str:
    raw = "\x1f".join(str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def iter_lines(path: Path, limit: int = MAX_SCAN_BYTES) -> Iterator[tuple[int, str]]:
    """Yield (1-based row, line) for at most ``limit`` bytes of a file.

    Bytes that are not UTF-8 are read as Latin-1, so a binary's embedded
    strings are still scanned. Very long lines are cut, not skipped.
    """
    with path.open("rb") as handle:
        data = handle.read(limit)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    for number, line in enumerate(text.splitlines(), start=1):
        yield number, line[:MAX_LINE_CHARS]


def _file_citation(input_dir: Path, rel: str, digest: str, row: int) -> Citation:
    return Citation(artifact_id=f"file-{digest[:16]}", source_file=rel, sha256=digest, row=row)


# --------------------------------------------------------------------------
# Core pipeline agent
# --------------------------------------------------------------------------


class CorePipelineAgent:
    """Run the proven core pipeline. Its report is the authoritative record."""

    name = "core_pipeline"

    def run(self, ctx: AgentContext, store: CaseStore, tools: ToolRegistry) -> AgentResult:
        core_dir = ctx.run_dir / "core"
        core_dir.mkdir(parents=True, exist_ok=True)
        provider = None if ctx.llm in {"off", "none"} else ctx.llm
        config = PipelineConfig(
            case_id=ctx.case_id,
            input_dir=ctx.input_dir,
            output_dir=core_dir,
            enable_llama=provider not in {None, "off"},
            llama_endpoint=ctx.llama_endpoint,
            llama_model=ctx.llama_model,
            llm_provider=provider or "off",
            rules_dir=ctx.rules_dir,
        )
        tools.allow("run_case", run_case)
        report = tools.call("run_case", config)
        store.add_findings(self.name, list(report.findings))
        return AgentResult(
            self.name,
            finding_count=len(report.findings),
            notes={
                "report": "core/case_report.json",
                "manifest": "core/run_manifest.json",
                "dropped_uncited": report.summary.get("dropped_uncited", 0),
                "dropped_unsupported": report.summary.get("dropped_unsupported", 0),
                "timeline_events": len(report.timeline),
            },
        )


# --------------------------------------------------------------------------
# Line-rule agents
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LineRule:
    rule_id: str
    pattern: re.Pattern[str]
    title: str
    severity: str
    tactic: str
    technique_id: str = ""
    recommendation: str = ""
    # When set, the line must also match this pattern. Used for phrases
    # that are common in ordinary writing unless they address a machine.
    requires: re.Pattern[str] | None = None

    def matches(self, line: str) -> bool:
        if not self.pattern.search(line):
            return False
        return self.requires is None or bool(self.requires.search(line))


# Characters that change how text displays or tokenises without being seen:
# zero-width spaces and joiners, soft hyphen, word joiner, BOM, and the
# bidirectional overrides and isolates.
_INVISIBLE = dict.fromkeys(map(ord, "\u00ad\u200b\u200c\u200d\u2060\ufeff"), None)
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def normalise_for_rules(line: str) -> str:
    """Fold full-width and compatibility letters and drop invisible characters."""
    return unicodedata.normalize("NFKC", line).translate(_INVISIBLE)


def hidden_text_signal(line: str) -> bool:
    """True when a line hides text: a bidi override, or an invisible character between letters."""
    if any(ch in _BIDI for ch in line):
        return True
    return bool(re.search(r"\w[\u200b\u200c\u200d\u2060\u00ad]+\w", line))


class LineRuleAgent:
    """Scan text-bearing files line by line against fixed rules."""

    name = "line_rules"
    kinds: tuple[str, ...] = ("text", "timeline_export")
    rules: tuple[LineRule, ...] = ()
    confidence = 0.7

    def files(self, ctx: AgentContext) -> list[str]:
        paths: list[str] = []
        for kind in self.kinds:
            paths.extend(ctx.profile.kinds.get(kind, []))
        return sorted(set(paths))

    def scan_file(self, ctx: AgentContext, rel: str) -> tuple[list[Finding], int]:
        path = ctx.input_dir / rel
        digest = sha256_file(path).lower()
        findings: list[Finding] = []
        hits = 0
        seen_rules: set[str] = set()
        for row, line in iter_lines(path):
            # Folding can lengthen a line (one character can become 18), so cut after it.
            folded = normalise_for_rules(line)[:MAX_LINE_CHARS]
            for rule in self.rules:
                if rule.rule_id in seen_rules:
                    continue
                if rule.rule_id == "hidden-text":
                    if not hidden_text_signal(line):
                        continue
                elif not rule.matches(folded):
                    continue
                hits += 1
                seen_rules.add(rule.rule_id)
                findings.append(Finding(
                    finding_id=stable_id(self.name, rel, row, rule.rule_id),
                    title=rule.title,
                    severity=rule.severity,
                    confidence=self.confidence,
                    tactic=rule.tactic,
                    technique_id=rule.technique_id,
                    evidence=[f"rule={rule.rule_id}", f"file={rel}", f"row={row}", f"line_sha256={line_digest(line)}"],
                    recommendation=rule.recommendation,
                    citations=[_file_citation(ctx.input_dir, rel, digest, row)],
                    origin="detector",
                ))
                if len(findings) >= MAX_FINDINGS_PER_FILE:
                    return findings, hits
        return findings, hits

    def run(self, ctx: AgentContext, store: CaseStore, tools: ToolRegistry) -> AgentResult:
        tools.allow("scan_file", lambda rel: self.scan_file(ctx, rel))
        findings: list[Finding] = []
        flagged: list[str] = []
        files = self.files(ctx)
        for rel in files:
            found, _ = tools.call("scan_file", rel)
            if found:
                flagged.append(rel)
            findings.extend(found)
        store.add_findings(self.name, findings)
        return AgentResult(self.name, finding_count=len(findings),
                           notes={"files_scanned": len(files), "files_flagged": flagged})


def _rx(text: str) -> re.Pattern[str]:
    return re.compile(text.replace(".*", r"[^\n]{0,400}"), re.IGNORECASE)


class InjectionSentinelAgent(LineRuleAgent):
    """Flag evidence that tries to give instructions to an AI analyst.

    A file that matches is reported as a finding and listed as hostile.
    The coordinator never quotes hostile files, and the draft warns the
    analyst to read them only in a viewer that does not call a model.
    """

    name = "injection_sentinel"
    kinds = ("text", "timeline_export", "binary", "other")
    confidence = 0.8
    _rec = "Treat this file as hostile input. Review it in a plain viewer, not through a model."
    # Words that show a line is addressed to a model rather than a person.
    _to_machine = _rx(r"\b(ai|a\.i\.|assistant|model|llm|chatbot|gpt|claude|llama|copilot|analy[sz](er|is tool)|"
                      r"triage tool|language model)\b|^\W*(system|assistant)\s*:|"
                      r"\b(benign|clean|safe|no (threats?|findings?|malware))\b")
    rules = (
        LineRule("ignore-instructions",
                 _rx(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all|earlier)\b.{0,40}"
                     r"\b(instructions?|prompts?|rules|directions)\b"),
                 "Evidence contains a prompt-injection phrase", "high", "defense-evasion", "T1036", _rec,
                 requires=_to_machine),
        LineRule("role-override",
                 _rx(r"\b(you are now|act as|pretend to be|new instructions?:|system prompt|assistant:)\b"),
                 "Evidence contains text that tries to redefine an AI's role", "medium", "defense-evasion", "T1036", _rec),
        LineRule("verdict-steer",
                 _rx(r"\b(report|mark|classify|label|conclude)\b.{0,40}\b(as )?(benign|clean|safe|"
                     r"no (threats?|findings?|malware))\b"),
                 "Evidence contains text that tries to steer the verdict to clean", "high", "defense-evasion",
                 "T1562", _rec),
        LineRule("hide-findings",
                 _rx(r"\b(do not|don't|never)\b.{0,30}\b(report|mention|flag|include)\b"),
                 "Evidence contains text asking an analyst tool to hide results", "medium", "defense-evasion",
                 "T1562", _rec, requires=_to_machine),
        LineRule("hidden-text", re.compile(r"(?!)"),
                 "Evidence hides text with invisible or right-to-left control characters", "medium",
                 "defense-evasion", "T1036.002", _rec),
        LineRule("chat-markup",
                 _rx(r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<<SYS>>"),
                 "Evidence contains model chat-control tokens", "high", "defense-evasion", "T1036", _rec),
    )


class SecretsSweepAgent(LineRuleAgent):
    """Find credentials and keys left in evidence."""

    name = "secrets_sweep"
    confidence = 0.75
    _rec = "Confirm whether the credential is live, then rotate it and check where it was used."
    rules = (
        LineRule("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
                 "Private key material found in evidence", "high", "credential-access", "T1552.004", _rec),
        LineRule("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
                 "Cloud access key found in evidence", "high", "credential-access", "T1552.001", _rec),
        LineRule("password-assignment",
                 # The value must look like a secret (6+ chars with a digit or symbol), so
                 # "reset your password: visit the portal" is not a hit.
                 _rx(r"(?<![a-z])(password|passwd|pass)\s*[:=]\s*['\"]?(?=[^\s'\"]{0,128}[\d!@#$%^&*_+\-])"
                     r"(?![/\\])[^\s'\",;]{6,128}"),
                 "Plaintext password found in evidence", "medium", "credential-access", "T1552.001", _rec),
        LineRule("bearer-token", re.compile(r"\b(ghp|gho|github_pat|xox[bp]|sk-[a-zA-Z0-9]{2})_?[A-Za-z0-9_\-]{16,}"),
                 "API token found in evidence", "high", "credential-access", "T1552.001", _rec),
        LineRule("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"),
                 "Chat webhook URL found in evidence", "medium", "credential-access", "T1552.001", _rec),
        LineRule("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
                 "Google API key found in evidence", "high", "credential-access", "T1552.001", _rec),
        LineRule("azure-storage-key", _rx(r"accountkey=[a-z0-9+/]{80,}={0,2}"),
                 "Cloud storage account key found in evidence", "high", "credential-access", "T1552.001", _rec),
        LineRule("payment-secret-key", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b"),
                 "Payment provider secret key found in evidence", "high", "credential-access", "T1552.001", _rec),
        LineRule("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,4096}\.eyJ[A-Za-z0-9_\-]{10,4096}\.[A-Za-z0-9_\-]{10,4096}"),
                 "Signed session token (JWT) found in evidence", "medium", "credential-access", "T1528", _rec),
        LineRule("ntlm-hash-dump", re.compile(r"^[^:\s]{1,64}:\d{1,10}:[0-9a-fA-F]{32}:[0-9a-fA-F]{32}:::"),
                 "Password hash dump (user:rid:lm:nt) found in evidence", "critical", "credential-access",
                 "T1003.002", _rec),
        LineRule("ntds-or-sam-copy-cmd", _rx(r"(secretsdump|impacket|hashdump|lsadump|ntds\.dit)"),
                 "Credential dumping tool name or AD database reference in text", "medium", "credential-access",
                 "T1003", _rec),
        LineRule("mimikatz-output", _rx(r"\b(sekurlsa::|lsadump::|kerberos::golden|mimikatz)\b"),
                 "Credential-dumping tool output or command found", "critical", "credential-access", "T1003", _rec),
    )


# --------------------------------------------------------------------------
# Memory agent
# --------------------------------------------------------------------------


def volatility_available() -> tuple[bool, str]:
    if shutil.which("vol") or importlib.util.find_spec("volatility3") is not None:
        return True, ""
    return False, "Volatility 3 is not installed (pip install 'auto-forensics-framework[memory]')"


SUSPICIOUS_CMDLINE = (
    ("encoded-powershell", _rx(r"powershell[^\n]{0,400}\s-(e|en|enc|encodedcommand)\s"), "high", "execution",
     "T1059.001"),
    ("temp-execution", _rx(r"\\(temp|appdata\\local\\temp|downloads)\\[^\\]+\.(exe|dll|scr)"), "medium",
     "execution", "T1204"),
    ("lsass-access", _rx(r"(procdump|comsvcs\.dll)[^\n]{0,400}lsass"), "critical", "credential-access", "T1003.001"),
)


class MemoryAgent:
    """Run Volatility 3 windows.cmdline on each memory image and apply rules."""

    name = "memory"
    timeout_seconds = 900

    def run(self, ctx: AgentContext, store: CaseStore, tools: ToolRegistry) -> AgentResult:
        tools.allow("volatility_cmdline", self._cmdline)
        findings: list[Finding] = []
        errors: list[str] = []
        for rel in ctx.profile.kinds.get("memory_image", []):
            path = ctx.input_dir / rel
            try:
                rows = tools.call("volatility_cmdline", path)
            except Exception as exc:  # noqa: BLE001 - one bad image must not stop the run
                errors.append(f"{rel}: {type(exc).__name__}")
                continue
            digest = sha256_file(path).lower()
            for index, row in enumerate(rows, start=1):
                args = str(row.get("Args") or "")
                for rule_id, pattern, severity, tactic, technique in SUSPICIOUS_CMDLINE:
                    if pattern.search(args):
                        findings.append(Finding(
                            finding_id=stable_id(self.name, rel, index, rule_id),
                            title=f"Memory: process command line matches {rule_id}",
                            severity=severity,
                            confidence=0.7,
                            tactic=tactic,
                            technique_id=technique,
                            evidence=[f"rule={rule_id}", f"pid={row.get('PID')}", f"image={rel}",
                                      f"cmdline_sha256={line_digest(args)}"],
                            recommendation="Confirm the process tree and dump the process for analysis.",
                            citations=[Citation(f"file-{digest[:16]}", rel, digest, row=index)],
                        ))
        store.add_findings(self.name, findings)
        status = "partial" if errors and findings else ("error" if errors else "ok")
        return AgentResult(self.name, status=status, detail="; ".join(errors), finding_count=len(findings))

    def _cmdline(self, image: Path) -> list[dict[str, Any]]:
        command = [shutil.which("vol") or "vol", "-q", "-r", "json", "-f", str(image), "windows.cmdline"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_seconds, check=True)
        data = json.loads(completed.stdout or "[]")
        return data if isinstance(data, list) else []


# --------------------------------------------------------------------------
# Archive agent
# --------------------------------------------------------------------------


class ArchiveAgent:
    """Extract evidence ZIPs into the run folder and analyse their contents.

    Each archive gets its own core run and line-rule scans. Their findings
    are re-cited as ``<archive>!<member>`` and submitted under this agent's
    name; the coordinator verifies them against the extracted copies.
    """

    name = "archive"

    def run(self, ctx: AgentContext, store: CaseStore, tools: ToolRegistry) -> AgentResult:
        from auto_forensics.case_store import MemoryCaseStore

        from .archives import SEPARATOR, extract_zip
        from .triage import profile_evidence

        tools.allow("extract_zip", extract_zip)
        members_out: list[dict[str, Any]] = []
        hostile: list[str] = []
        errors: list[str] = []
        skipped: list[str] = []
        submitted: list[Finding] = []
        for rel in ctx.profile.kinds.get("archive", []):
            path = ctx.input_dir / rel
            if not (rel.lower().endswith(".zip") or path.read_bytes()[:4] == b"PK\x03\x04"):
                skipped.append(rel)
                continue
            digest = sha256_file(path).lower()
            folder = f"{Path(rel).stem[:40]}-{digest[:8]}"
            extracted = ctx.run_dir / "archives" / folder
            try:
                members = tools.call("extract_zip", path, rel, digest, extracted)
            except Exception as exc:  # noqa: BLE001 - a refused archive is reported, not fatal
                errors.append(f"{rel}: {exc}")
                continue
            for member in members:
                record = member.to_dict()
                record["folder"] = folder
                members_out.append(record)
            sub_ctx = AgentContext(case_id=ctx.case_id, input_dir=extracted,
                                   run_dir=ctx.run_dir / "archive-runs" / folder, profile=profile_evidence(extracted),
                                   llm=ctx.llm, llama_endpoint=ctx.llama_endpoint, llama_model=ctx.llama_model,
                                   rules_dir=ctx.rules_dir)
            sub_store = MemoryCaseStore()
            for agent_cls in (CorePipelineAgent, InjectionSentinelAgent, SecretsSweepAgent):
                agent = agent_cls()
                try:
                    result = agent.run(sub_ctx, sub_store, ToolRegistry(worker=f"archive/{agent.name}", store=sub_store))
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{rel} {agent.name}: {type(exc).__name__}")
                    continue
                if agent.name == "injection_sentinel":
                    hostile.extend(f"{rel}{SEPARATOR}{item}" for item in result.notes.get("files_flagged", []))
            for finding in sub_store.findings():
                for citation in finding.citations:
                    citation.source_file = f"{rel}{SEPARATOR}{citation.source_file}"
                finding.finding_id = stable_id("arc", finding.finding_id, rel)
                submitted.append(finding)
        store.add_findings(self.name, submitted)
        status = "error" if errors and not members_out else ("partial" if errors else "ok")
        return AgentResult(self.name, status=status, detail="; ".join(errors)[:600], finding_count=len(submitted),
                           notes={"members": members_out, "files_flagged": hostile, "not_zip": skipped})


AGENTS: dict[str, Callable[[], Any]] = {
    "core_pipeline": CorePipelineAgent,
    "injection_sentinel": InjectionSentinelAgent,
    "secrets_sweep": SecretsSweepAgent,
    "memory": MemoryAgent,
    "archive": ArchiveAgent,
}


def agent_availability() -> dict[str, tuple[bool, str]]:
    return {"memory": volatility_available()}
