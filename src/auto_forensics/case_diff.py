"""Case comparison and diff engine for forensic analysis.

Enables comparison of two cases to identify common/different
IOCs, findings, artifacts, and MITRE ATT&CK techniques.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .db_backend import DatabaseBackend


class DiffType(Enum):
    """What to include in the diff output."""

    COMMON_ONLY = "common_only"
    DIFF_ONLY = "diff_only"
    ALL = "all"


@dataclass(slots=True)
class CaseDiffResult:
    """Diff result for comparing two cases."""

    case_a_id: str
    case_b_id: str

    # IOCs
    common_iocs: list[dict] = field(default_factory=list)
    only_in_a_iocs: list[dict] = field(default_factory=list)
    only_in_b_iocs: list[dict] = field(default_factory=list)

    # Findings
    common_findings: list[dict] = field(default_factory=list)
    only_in_a_findings: list[dict] = field(default_factory=list)
    only_in_b_findings: list[dict] = field(default_factory=list)

    # Artifacts
    common_artifacts: list[dict] = field(default_factory=list)
    only_in_a_artifacts: list[dict] = field(default_factory=list)
    only_in_b_artifacts: list[dict] = field(default_factory=list)

    # Risk comparison
    risk_score_comparison: dict[str, Any] = field(default_factory=dict)

    # MITRE ATT&CK
    matched_techniques: list[str] = field(default_factory=list)
    unique_to_a_techniques: list[str] = field(default_factory=list)
    unique_to_b_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_a_id": self.case_a_id,
            "case_b_id": self.case_b_id,
            "iocs": {
                "common": len(self.common_iocs),
                "only_in_a": len(self.only_in_a_iocs),
                "only_in_b": len(self.only_in_b_iocs),
            },
            "findings": {
                "common": len(self.common_findings),
                "only_in_a": len(self.only_in_a_findings),
                "only_in_b": len(self.only_in_b_findings),
            },
            "artifacts": {
                "common": len(self.common_artifacts),
                "only_in_a": len(self.only_in_a_artifacts),
                "only_in_b": len(self.only_in_b_artifacts),
            },
            "risk_score": self.risk_score_comparison,
            "techniques": {
                "matched": self.matched_techniques,
                "unique_to_a": self.unique_to_a_techniques,
                "unique_to_b": self.unique_to_b_techniques,
            },
        }


class CaseDiffer:
    """Compares two forensic cases and generates diff reports."""

    def __init__(self, db: DatabaseBackend) -> None:
        self.db = db

    def compare_cases(
        self,
        case_a_id: str,
        case_b_id: str,
        diff_type: DiffType = DiffType.ALL,
    ) -> CaseDiffResult:
        """Compare two cases and return a detailed diff.

        Args:
            case_a_id: First case ID
            case_b_id: Second case ID
            diff_type: What to include in output

        Returns:
            CaseDiffResult with all comparison data
        """
        result = CaseDiffResult(case_a_id=case_a_id, case_b_id=case_b_id)

        # Load data from both cases
        overview_a = self.db.case_overview(case_a_id)
        overview_b = self.db.case_overview(case_b_id)

        # Compare IOCs
        iocs_a = {
            self._ioc_key(i): i
            for i in overview_a.get("iocs", [])
        }
        iocs_b = {
            self._ioc_key(i): i
            for i in overview_b.get("iocs", [])
        }
        common_iocs = set(iocs_a.keys()) & set(iocs_b.keys())
        only_a_iocs = set(iocs_a.keys()) - set(iocs_b.keys())
        only_b_iocs = set(iocs_b.keys()) - set(iocs_a.keys())

        if diff_type in (DiffType.ALL, DiffType.COMMON_ONLY):
            result.common_iocs = [iocs_a[k] for k in common_iocs]
        if diff_type in (DiffType.ALL, DiffType.DIFF_ONLY):
            result.only_in_a_iocs = [iocs_a[k] for k in only_a_iocs]
            result.only_in_b_iocs = [iocs_b[k] for k in only_b_iocs]

        # Compare Findings
        findings_a = {
            self._finding_key(f): f
            for f in overview_a.get("findings", [])
        }
        findings_b = {
            self._finding_key(f): f
            for f in overview_b.get("findings", [])
        }
        common_findings = set(findings_a.keys()) & set(
            findings_b.keys()
        )
        only_a_findings = set(findings_a.keys()) - set(
            findings_b.keys()
        )
        only_b_findings = set(findings_b.keys()) - set(
            findings_a.keys()
        )

        if diff_type in (DiffType.ALL, DiffType.COMMON_ONLY):
            result.common_findings = [
                findings_a[k] for k in common_findings
            ]
        if diff_type in (DiffType.ALL, DiffType.DIFF_ONLY):
            result.only_in_a_findings = [
                findings_a[k] for k in only_a_findings
            ]
            result.only_in_b_findings = [
                findings_b[k] for k in only_b_findings
            ]

        # Compare Artifacts
        artifacts_a = {
            self._artifact_key(a): a
            for a in overview_a.get("artifacts", [])
        }
        artifacts_b = {
            self._artifact_key(a): a
            for a in overview_b.get("artifacts", [])
        }
        common_artifacts = set(artifacts_a.keys()) & set(
            artifacts_b.keys()
        )
        only_a_artifacts = set(artifacts_a.keys()) - set(
            artifacts_b.keys()
        )
        only_b_artifacts = set(artifacts_b.keys()) - set(
            artifacts_a.keys()
        )

        if diff_type in (DiffType.ALL, DiffType.COMMON_ONLY):
            result.common_artifacts = [
                artifacts_a[k] for k in common_artifacts
            ]
        if diff_type in (DiffType.ALL, DiffType.DIFF_ONLY):
            result.only_in_a_artifacts = [
                artifacts_a[k] for k in only_a_artifacts
            ]
            result.only_in_b_artifacts = [
                artifacts_b[k] for k in only_b_artifacts
            ]

        # Risk score comparison
        summary_a = overview_a.get("summary", {})
        summary_b = overview_b.get("summary", {})
        risk_a = summary_a.get("risk_score", 0) or summary_a.get(
            "total_risk_score", 0
        )
        risk_b = summary_b.get("risk_score", 0) or summary_b.get(
            "total_risk_score", 0
        )
        average_a = summary_a.get("average_risk_score", 0)
        average_b = summary_b.get("average_risk_score", 0)
        result.risk_score_comparison = {
            "case_a_score": risk_a,
            "case_b_score": risk_b,
            "delta": risk_b - risk_a,
            "case_a_average": average_a,
            "case_b_average": average_b,
        }

        # MITRE ATT&CK Techniques
        techs_a = self._extract_techniques(overview_a.get("findings", []))
        techs_b = self._extract_techniques(overview_b.get("findings", []))
        result.matched_techniques = list(techs_a & techs_b)
        result.unique_to_a_techniques = list(techs_a - techs_b)
        result.unique_to_b_techniques = list(techs_b - techs_a)

        return result

    def _ioc_key(self, ioc: dict) -> str:
        """Create a hashable key for an IOC."""
        ioc_type = str(ioc.get("ioc_type") or ioc.get("type", ""))
        value = str(ioc.get("value", ""))
        return f"{ioc_type.lower()}:{value.lower()}"

    def _finding_key(self, finding: dict) -> str:
        """Create a hashable key for a finding."""
        title = str(finding.get("title") or finding.get("rule_name", ""))
        sev = str(finding.get("severity", ""))
        tech = str(finding.get("technique", ""))
        return f"{sev}:{tech}:{title.lower()}"

    def _artifact_key(self, artifact: dict) -> str:
        """Create a hashable key for an artifact."""
        path = str(artifact.get("rel_path", ""))
        return path.lower()

    def _extract_techniques(self, findings: list[dict]) -> set[str]:
        """Extract unique MITRE technique IDs from findings."""
        techs: set[str] = set()
        for f in findings:
            tech = str(f.get("technique", ""))
            if tech and tech != "—":
                techs.add(tech)
            tags = f.get("tags", [])
            for tag in tags:
                if isinstance(tag, str) and tag.startswith("attack.t"):
                    techs.add(tag[6:])  # Extract T1234 format
        return techs

    def compare_iocs(
        self, iocs_a: list[dict], iocs_b: list[dict]
    ) -> tuple[list[dict], list[dict], list[dict]]:
        """Compare two lists of IOCs.

        Returns: (common, only_in_a, only_in_b)
        """
        keys_a = {self._ioc_key(i): i for i in iocs_a}
        keys_b = {self._ioc_key(i): i for i in iocs_b}
        common = set(keys_a.keys()) & set(keys_b.keys())
        only_a = set(keys_a.keys()) - set(keys_b.keys())
        only_b = set(keys_b.keys()) - set(keys_a.keys())
        return (
            [keys_a[k] for k in common],
            [keys_a[k] for k in only_a],
            [keys_b[k] for k in only_b],
        )

    def compare_findings(
        self, findings_a: list[dict], findings_b: list[dict]
    ) -> tuple[list[dict], list[dict], list[dict]]:
        """Compare two lists of findings.

        Returns: (common, only_in_a, only_in_b)
        """
        keys_a = {self._finding_key(f): f for f in findings_a}
        keys_b = {self._finding_key(f): f for f in findings_b}
        common = set(keys_a.keys()) & set(keys_b.keys())
        only_a = set(keys_a.keys()) - set(keys_b.keys())
        only_b = set(keys_b.keys()) - set(keys_a.keys())
        return (
            [keys_a[k] for k in common],
            [keys_a[k] for k in only_a],
            [keys_b[k] for k in only_b],
        )

    def generate_diff_report(
        self, diff_result: CaseDiffResult, fmt: str = "md"
    ) -> str:
        """Generate a formatted diff report.

        Args:
            diff_result: The comparison result
            fmt: Output format - "md" (markdown), "json", "html"

        Returns:
            Formatted report string
        """
        if fmt == "json":
            return json.dumps(diff_result.to_dict(), indent=2)

        if fmt == "html":
            return self._generate_html_report(diff_result)

        return self._generate_markdown_report(diff_result)

    def _generate_markdown_report(self, result: CaseDiffResult) -> str:
        """Generate a Markdown formatted diff report."""
        lines: list[str] = [
            "# Case Diff Report",
            "",
            f"**Case A:** {result.case_a_id}",
            f"**Case B:** {result.case_b_id}",
            "",
            "---",
            "",
        ]

        # Risk comparison
        risk = result.risk_score_comparison
        lines.extend([
            "## Risk Score Comparison",
            "",
            f"| Metric | {result.case_a_id} | {result.case_b_id} |",
            "|--------|---------|---------|",
            f"| Total Risk | {risk.get('case_a_score', 0)} | {risk.get('case_b_score', 0)} |",
            f"| Average Risk | {risk.get('case_a_average', 0):.1f} | {risk.get('case_b_average', 0):.1f} |",
            f"| Delta | | {risk.get('delta', 0):+d} |",
            "",
        ])

        # IOCs
        lines.extend([
            "## IOCs",
            "",
            f"- **Common:** {len(result.common_iocs)} IOCs",
            f"- **Only in {result.case_a_id}:** {len(result.only_in_a_iocs)} IOCs",
            f"- **Only in {result.case_b_id}:** {len(result.only_in_b_iocs)} IOCs",
            "",
        ])
        if result.common_iocs:
            lines.extend(["### Common IOCs", ""])
            for ioc in result.common_iocs[:10]:
                ioc_type = str(ioc.get('ioc_type') or ioc.get('type', ''))
                value = str(ioc.get('value', ''))
                lines.append(f"- `{ioc_type}`: {value[:60]}")
            if len(result.common_iocs) > 10:
                lines.append(f"- *...and {len(result.common_iocs) - 10} more*")
            lines.append("")

        # Findings
        lines.extend([
            "## Findings",
            "",
            f"- **Common:** {len(result.common_findings)} findings",
            f"- **Only in {result.case_a_id}:** {len(result.only_in_a_findings)} findings",
            f"- **Only in {result.case_b_id}:** {len(result.only_in_b_findings)} findings",
            "",
        ])
        if result.common_findings:
            lines.extend(["### Common Findings", ""])
            for f in result.common_findings[:10]:
                sev = str(f.get('severity', ''))
                title = str(f.get('title') or f.get('rule_name', ''))
                lines.append(f"- [{sev.upper()}] {title[:60]}")
            lines.append("")

        # MITRE ATT&CK
        lines.extend([
            "## MITRE ATT&CK Techniques",
            "",
            f"- **Matched:** {len(result.matched_techniques)} techniques",
            f"- **Unique to {result.case_a_id}:** {len(result.unique_to_a_techniques)} techniques",
            f"- **Unique to {result.case_b_id}:** {len(result.unique_to_b_techniques)} techniques",
            "",
        ])
        if result.matched_techniques:
            lines.extend(["### Matched Techniques", ""])
            for t in result.matched_techniques:
                lines.append(f"- {t}")
            lines.append("")

        return "\n".join(lines)

    def _generate_html_report(self, result: CaseDiffResult) -> str:
        """Generate an HTML formatted diff report."""
        risk = result.risk_score_comparison
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Case Diff Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 2em; }}
        h1 {{ color: #333; }}
        h2 {{ color: #555; border-bottom: 1px solid #ddd; }}
        table {{ border-collapse: collapse; margin: 1em 0; }}
        th, td {{ border: 1px solid #ddd; padding: 0.5em; }}
        th {{ background: #f5f5f5; }}
        .metric {{ font-weight: bold; }}
        .common {{ color: #2c7fb8; }}
        .unique-a {{ color: #e34a33; }}
        .unique-b {{ color: #31a354; }}
    </style>
</head>
<body>
    <h1>Case Diff Report</h1>
    <p><strong>Case A:</strong> {result.case_a_id}</p>
    <p><strong>Case B:</strong> {result.case_b_id}</p>
    
    <h2>Risk Score Comparison</h2>
    <table>
        <tr><th>Metric</th><th>{result.case_a_id}</th><th>{result.case_b_id}</th></tr>
        <tr>
            <td class="metric">Total Risk</td>
            <td>{risk.get('case_a_score', 0)}</td>
            <td>{risk.get('case_b_score', 0)}</td>
        </tr>
        <tr>
            <td class="metric">Delta</td>
            <td>—</td>
            <td>{risk.get('delta', 0):+d}</td>
        </tr>
    </table>
    
    <h2>IOCs</h2>
    <ul>
        <li class="common">
            Common: {len(result.common_iocs)} IOCs</li>
        <li class="unique-a">
            Only in {result.case_a_id}: {len(result.only_in_a_iocs)} IOCs</li>
        <li class="unique-b">
            Only in {result.case_b_id}: {len(result.only_in_b_iocs)} IOCs</li>
    </ul>
    
    <h2>Findings</h2>
    <ul>
        <li class="common">
            Common: {len(result.common_findings)} findings</li>
        <li class="unique-a">
            Only in {result.case_a_id}: {len(result.only_in_a_findings)} findings</li>
        <li class="unique-b">
            Only in {result.case_b_id}: {len(result.only_in_b_findings)} findings</li>
    </ul>
    
    <h2>MITRE ATT&amp;CK Techniques</h2>
    <ul>
        <li>Matched: {len(result.matched_techniques)} techniques</li>
        <li>Unique to {result.case_a_id}: {len(result.unique_to_a_techniques)} techniques</li>
        <li>Unique to {result.case_b_id}: {len(result.unique_to_b_techniques)} techniques</li>
    </ul>
</body>
</html>"""
        return html
