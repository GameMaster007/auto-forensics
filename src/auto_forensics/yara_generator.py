"""YARA rule generator for Auto Forensics.

Automatically generates YARA rules from binary samples by extracting
unique strings and byte patterns.
"""
from __future__ import annotations

import hashlib
import logging
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Common strings to exclude from rules
_COMMON_STRINGS = {
    "http", "https", "www", "com", "org", "net", "dll", "exe",
    "windows", "microsoft", "system32", "program files",
    "get", "post", "content-type", "user-agent",
    "kernel32", "ntdll", "advapi32", "user32",
}

# Magic bytes for common file formats
_MAGIC_BYTES = {
    b"MZ": "executable",
    b"\\x7fELF": "elf",
    b"\\x89PNG": "png",
    b"\\xff\\xd8\\xff": "jpeg",
}


@dataclass(slots=True)
class YaraRule:
    """A generated YARA rule."""
    rule_name: str
    description: str
    author: str
    date: str
    strings: list[dict[str, Any]]
    condition: str
    meta: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_yara(self) -> str:
        """Convert to YARA rule text."""
        lines = [f"rule {self.rule_name}"]

        if self.tags:
            lines[0] += f" : {' '.join(self.tags)}"

        lines.append("{")

        # Meta section
        lines.append("    meta:")
        lines.append(f'        description = "{self.description}"')
        lines.append(f'        author = "{self.author}"')
        lines.append(f'        date = "{self.date}"')
        for key, value in self.meta.items():
            if isinstance(value, str):
                lines.append(f'        {key} = "{value}"')
            else:
                lines.append(f'        {key} = {value}')

        # Strings section
        if self.strings:
            lines.append("")
            lines.append("    strings:")
            for s in self.strings:
                modifier = s.get("modifier", "")
                if modifier:
                    modifier = f" {modifier}"
                lines.append(f'        ${s["name"]} = {s["value"]}{modifier}')

        # Condition section
        lines.append("")
        lines.append("    condition:")
        lines.append(f"        {self.condition}")

        lines.append("}")
        return "\\n".join(lines)


@dataclass(slots=True)
class StringCandidate:
    """A candidate string for YARA rule."""
    value: str | bytes
    offset: int
    encoding: str  # 'ascii', 'wide', 'utf8'
    is_unique: bool
    score: float


class YaraRuleGenerator:
    """Generates YARA rules from binary samples."""

    def __init__(self, min_string_length: int = 4, max_strings: int = 20):
        """Initialize the generator.

        Args:
            min_string_length: Minimum length for string extraction.
            max_strings: Maximum number of strings to include in rule.
        """
        self.min_string_length = min_string_length
        self.max_strings = max_strings
        self._string_counter = 0

    def generate_rule(
        self,
        sample_path: Path,
        rule_name: str | None = None,
        description: str | None = None,
        author: str = "Auto Forensics",
        tags: list[str] | None = None,
    ) -> YaraRule:
        """Generate a YARA rule from a sample file.

        Args:
            sample_path: Path to the sample file.
            rule_name: Name for the rule (auto-generated if None).
            description: Rule description.
            author: Rule author.
            tags: YARA rule tags.

        Returns:
            Generated YARA rule.
        """
        sample_path = Path(sample_path)
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        # Read sample
        data = sample_path.read_bytes()

        # Auto-generate rule name if not provided
        if rule_name is None:
            file_hash = hashlib.sha256(data).hexdigest()[:16]
            rule_name = f"malware_{file_hash}"

        if description is None:
            description = f"Auto-generated rule for {sample_path.name}"

        # Extract features
        strings = self._extract_strings(data)
        byte_patterns = self._extract_byte_patterns(data)

        # Build rule
        self._string_counter = 0
        rule_strings = []

        # Add high-scoring strings
        for s in strings[: self.max_strings // 2]:
            rule_strings.append(self._format_string(s))

        # Add byte patterns
        for p in byte_patterns[:3]:
            rule_strings.append(p)

        # Build condition
        conditions = []
        if rule_strings:
            string_conditions = " or ".join(f"${s['name']}" for s in rule_strings)
            conditions.append(f"({string_conditions})")

        # Add file type checks
        conditions.append("filesize < 10MB")

        condition = " and ".join(conditions) if conditions else "true"

        # Generate metadata
        meta = {
            "hash_sha256": hashlib.sha256(data).hexdigest(),
            "file_size": len(data),
            "source_file": sample_path.name,
        }

        # Detect malware family
        family = self._detect_malware_family(strings)
        if family:
            meta["malware_family"] = family

        # Check for MITRE techniques
        mitre_techniques = self._detect_mitre_techniques(data, strings)
        if mitre_techniques:
            meta["mitre_techniques"] = ", ".join(mitre_techniques)

        from datetime import datetime

        return YaraRule(
            rule_name=rule_name,
            description=description,
            author=author,
            date=datetime.now().strftime("%Y-%m-%d"),
            strings=rule_strings,
            condition=condition,
            meta=meta,
            tags=tags or ["auto-generated"],
        )

    def _extract_strings(self, data: bytes) -> list[StringCandidate]:
        """Extract candidate strings from binary."""
        candidates: list[StringCandidate] = []

        # ASCII strings
        ascii_strings = re.findall(rb"[\\x20-\\x7e]{%d,}" % self.min_string_length, data)
        for s in ascii_strings:
            offset = data.find(s)
            is_common = s.lower().decode("ascii", errors="ignore") in _COMMON_STRINGS
            score = self._score_string(s, is_common)
            candidates.append(
                StringCandidate(
                    value=s.decode("ascii"),
                    offset=offset,
                    encoding="ascii",
                    is_unique=not is_common,
                    score=score,
                )
            )

        # Wide strings (UTF-16LE)
        wide_pattern = rb"(?:[\\x20-\\x7e]\\x00){%d,}" % self.min_string_length
        wide_matches = re.findall(wide_pattern, data)
        for s in wide_matches:
            offset = data.find(s)
            try:
                decoded = s.decode("utf-16le")
                is_common = decoded.lower() in _COMMON_STRINGS
                score = self._score_string(s, is_common) * 1.2  # Boost wide strings
                candidates.append(
                    StringCandidate(
                        value=decoded,
                        offset=offset,
                        encoding="wide",
                        is_unique=not is_common,
                        score=score,
                    )
                )
            except UnicodeDecodeError:
                continue

        # Sort by score (highest first)
        candidates.sort(key=lambda x: x.score, reverse=True)
        return candidates

    def _score_string(self, s: bytes, is_common: bool) -> float:
        """Score a string candidate."""
        if is_common:
            return 0.0

        score = len(s) * 0.1  # Longer strings score higher

        # Boost for suspicious patterns
        s_lower = s.lower()
        suspicious = [
            b"cmd.exe", b"powershell", b"http:", b"https:",
            b"base64", b"encrypted", b"payload",
        ]
        for pattern in suspicious:
            if pattern in s_lower:
                score += 2.0

        # Boost for unique-looking strings (high entropy)
        if len(s) >= 8:
            score += self._calculate_entropy(s) * 0.5

        return score

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0

        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += -p_x * (p_x).bit_length()

        return entropy

    def _extract_byte_patterns(self, data: bytes) -> list[dict[str, Any]]:
        """Extract unique byte patterns from binary."""
        patterns = []

        # Entry point pattern (first 16 bytes after MZ header)
        if data[:2] == b"MZ":
            try:
                pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
                if 0 < pe_offset < len(data) - 4:
                    sig = data[pe_offset:pe_offset + 4]
                    if sig == b"PE\\x00\\x00":
                        patterns.append({
                            "name": self._next_string_name(),
                            "value": f"{{ {hex_pattern(data[:16])} }}",
                            "modifier": "",
                            "type": "pe_header",
                        })
            except struct.error:
                pass

        # Rich header pattern (if present)
        rich_offset = data.find(b"Rich")
        if rich_offset > 0 and rich_offset + 8 < len(data):
            patterns.append({
                "name": self._next_string_name(),
                "value": f"{{ {hex_pattern(data[rich_offset:rich_offset + 8])} }}",
                "modifier": "",
                "type": "rich_header",
            })

        # Section names (first 8 bytes of each section)
        if len(data) > 0x200:
            patterns.append({
                "name": self._next_string_name(),
                "value": f"{{ {hex_pattern(data[0x200:0x208])} }}",
                "modifier": "",
                "type": "section_header",
            })

        return patterns

    def _next_string_name(self) -> str:
        """Generate next string name."""
        self._string_counter += 1
        return f"s{self._string_counter:02d}"

    def _format_string(self, candidate: StringCandidate) -> dict[str, Any]:
        """Format a string candidate for YARA."""
        name = self._next_string_name()

        if candidate.encoding == "wide":
            # For wide strings, use wide modifier
            value_bytes = candidate.value.encode("utf-16le")
            return {
                "name": name,
                "value": f'"{candidate.value}"',
                "modifier": "wide",
                "original": candidate,
            }
        else:
            return {
                "name": name,
                "value": f'"{candidate.value}"',
                "modifier": "",
                "original": candidate,
            }

    def _detect_malware_family(
        self,
        strings: list[StringCandidate],
    ) -> str | None:
        """Detect malware family from strings."""
        all_strings = " ".join(
            s.value.lower() if isinstance(s.value, str) else s.value.decode("ascii", errors="ignore")
            for s in strings
        )

        families = {
            "cobaltstrike": ["cobalt strike", "beacon", "stage", "payload"],
            "meterpreter": ["meterpreter", "metsrv", "stdapi"],
            "trickbot": ["trickbot", "trick", "bot", "pwgrab"],
            "emotet": ["emotet", "emo", "banker"],
            "dridex": ["dridex", "drid", "crypter"],
            "remcos": ["remcos", "rem", "rat"],
            "nanocore": ["nanocore", "nano", "core"],
            "darkcomet": ["darkcomet", "dcrat", "dark"],
        }

        scores: dict[str, int] = {}
        for family, indicators in families.items():
            score = sum(1 for ind in indicators if ind in all_strings)
            if score > 0:
                scores[family] = score

        if scores:
            return max(scores, key=scores.get)
        return None

    def _detect_mitre_techniques(
        self,
        data: bytes,
        strings: list[StringCandidate],
    ) -> list[str]:
        """Detect MITRE ATT&CK techniques from sample."""
        techniques = set()
        all_strings = " ".join(
            s.value.lower() if isinstance(s.value, str) else s.value.decode("ascii", errors="ignore")
            for s in strings
        )

        # T1055 - Process Injection
        if any(s in all_strings for s in ["virtualalloc", "writeprocessmemory", "createremotethread"]):
            techniques.add("T1055")

        # T1053 - Scheduled Task/Job
        if any(s in all_strings for s in ["schtasks", "taskscheduler", "cron"]):
            techniques.add("T1053")

        # T1071 - Application Layer Protocol
        if any(s in all_strings for s in ["http", "https", "post", "get", "socket"]):
            techniques.add("T1071")

        # T1083 - File and Directory Discovery
        if any(s in all_strings for s in ["findfirstfile", "readdirectory", "opendir"]):
            techniques.add("T1083")

        # T1082 - System Information Discovery
        if any(s in all_strings for s in ["getcomputername", "getusername", "getversion"]):
            techniques.add("T1082")

        # T1105 - Ingress Tool Transfer
        if any(s in all_strings for s in ["internetopen", "urldownload", "downloadfile"]):
            techniques.add("T1105")

        # T1112 - Modify Registry
        if any(s in all_strings for s in ["regcreatekey", "regsetvalue", "registry"]):
            techniques.add("T1112")

        # T1497 - Virtualization/Sandbox Evasion
        if any(s in all_strings for s in ["vmware", "virtualbox", "sandbox", "qemu"]):
            techniques.add("T1497")

        return sorted(list(techniques))

    def test_rule(
        self,
        rule: YaraRule,
        positive_samples: list[Path],
        negative_samples: list[Path],
    ) -> dict[str, Any]:
        """Test a YARA rule against known samples.

        Args:
            rule: YARA rule to test.
            positive_samples: Samples that should match.
            negative_samples: Samples that should not match.

        Returns:
            Test results with precision, recall, F1 score.
        """
        try:
            import yara
        except ImportError:
            return {"error": "yara-python not installed"}

        # Compile rule
        try:
            compiled = yara.compile(source=rule.to_yara())
        except Exception as e:
            return {"error": f"Rule compilation failed: {e}"}

        # Test positive samples
        tp = 0  # True positives
        fn = 0  # False negatives
        for sample in positive_samples:
            try:
                matches = compiled.match(str(sample))
                if matches:
                    tp += 1
                else:
                    fn += 1
            except Exception:
                fn += 1

        # Test negative samples
        fp = 0  # False positives
        tn = 0  # True negatives
        for sample in negative_samples:
            try:
                matches = compiled.match(str(sample))
                if matches:
                    fp += 1
                else:
                    tn += 1
            except Exception:
                tn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1_score": round(f1, 3),
            "accuracy": round((tp + tn) / (tp + tn + fp + fn), 3) if (tp + tn + fp + fn) > 0 else 0,
        }


def hex_pattern(data: bytes) -> str:
    """Convert bytes to YARA hex pattern."""
    return " ".join(f"{b:02X}" for b in data)


def suggest_rule_improvements(
    rule: YaraRule,
    fp_samples: list[Path],
) -> list[str]:
    """Suggest improvements based on false positives."""
    suggestions = []

    if len(rule.strings) > 20:
        suggestions.append(
            "Too many strings may cause performance issues. Consider using "
            "fewer, more unique strings."
        )

    if not any(s.get("modifier") == "nocase" for s in rule.strings):
        suggestions.append(
            "Consider using 'nocase' modifier for string matching to catch "
            "variants with different casing."
        )

    if "filesize" not in rule.condition:
        suggestions.append(
            "Add filesize constraint to condition to avoid matching "
            "unusually large files."
        )

    if len(fp_samples) > 0:
        suggestions.append(
            f"Rule matches {len(fp_samples)} benign samples. "
            "Consider adding more specific strings or conditions."
        )

    return suggestions
