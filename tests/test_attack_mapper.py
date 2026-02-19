from __future__ import annotations

import json
from pathlib import Path

from auto_forensics.attack_mapper import apply_attack_mapping, build_attack_navigator_layer, load_attack_techniques
from auto_forensics.models import Finding


def test_load_attack_techniques_and_apply_mapping(tmp_path: Path):
    stix_path = tmp_path / "attack.json"
    stix_path.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "attack-pattern",
                        "name": "Command and Scripting Interpreter",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1059"}
                        ],
                        "kill_chain_phases": [
                            {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    techniques = load_attack_techniques(stix_path)
    findings = [
        Finding(
            finding_id="f1",
            title="Powershell execution observed",
            severity="high",
            confidence=0.9,
            tactic="unknown",
            evidence=["powershell.exe -enc ..."],
        )
    ]

    mapped = apply_attack_mapping(findings, techniques)

    assert mapped[0].technique_id == "T1059"
    assert mapped[0].tactic == "execution"


def test_build_attack_navigator_layer_uses_finding_confidence():
    findings = [
        Finding(
            finding_id="f1",
            title="test",
            severity="medium",
            confidence=0.73,
            tactic="execution",
            technique_id="T1059",
        )
    ]
    layer = build_attack_navigator_layer("case-001", findings, techniques={})

    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"][0]["techniqueID"] == "T1059"
    assert layer["techniques"][0]["score"] == 73
