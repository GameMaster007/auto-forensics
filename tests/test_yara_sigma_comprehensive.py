from __future__ import annotations

import pytest
from pathlib import Path
from auto_forensics.models import TimelineEvent
from auto_forensics.yara_detector import scan_paths_with_yara
from auto_forensics.sigma_rules import evaluate_sigma_rules

def test_yara_matching_rules(tmp_path: Path):
    try:
        import yara
    except ImportError:
        pytest.skip("yara-python not installed")
        
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "test.yar").write_text("""
rule TestRule {
    strings:
        $a = "suspicious"
    condition:
        $a
}
""", encoding="utf-8")
    
    sample = tmp_path / "sample.bin"
    sample.write_text("this is suspicious", encoding="utf-8")
    
    findings, hints = scan_paths_with_yara([sample], rules_dir=rules_dir)
    
    assert len(findings) == 1
    assert findings[0].title == "YARA match: TestRule"
    assert "sample.bin" in findings[0].evidence[0]
    assert len(hints) == 1
    assert hints[0].event_type == "yara_match"

def test_yara_malformed_rule_skipped(tmp_path: Path):
    try:
        import yara
    except ImportError:
        pytest.skip("yara-python not installed")
        
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "bad.yar").write_text("invalid yara syntax", encoding="utf-8")
    (rules_dir / "good.yar").write_text("""
rule GoodRule {
    condition: true
}
""", encoding="utf-8")
    
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"test")
    
    # Should not crash, should just skip bad rule
    findings, hints = scan_paths_with_yara([sample], rules_dir=rules_dir)
    assert len(findings) >= 1
    assert any(f.title == "YARA match: GoodRule" for f in findings)

def test_sigma_matching_keywords(tmp_path: Path):
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
        
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    (rules_dir / "test.yml").write_text("""
title: Suspicious Execution
level: high
detection:
    keywords:
        - "whoami"
        - "net user"
    condition: keywords
""", encoding="utf-8")
    
    timeline = [
        TimelineEvent(
            timestamp=None,
            source="test",
            event_type="cmd",
            description="running whoami",
            risk_score=0,
            tags=[],
            related={}
        )
    ]
    
    findings = evaluate_sigma_rules(timeline, rules_dir)
    assert len(findings) == 1
    assert "Suspicious Execution" in findings[0].title
    assert findings[0].severity == "high"

def test_sigma_malformed_yaml_skipped(tmp_path: Path):
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
        
    rules_dir = tmp_path / "sigma"
    rules_dir.mkdir()
    (rules_dir / "bad.yml").write_text("!!binary | invalid", encoding="utf-8")
    (rules_dir / "good.yml").write_text("""
title: Good
level: low
detection:
    keywords: ["test"]
    condition: keywords
""", encoding="utf-8")
    
    timeline = [
        TimelineEvent(
            timestamp=None, source="src", event_type="evt", description="test",
            risk_score=0, tags=[], related={}
        )
    ]
    
    findings = evaluate_sigma_rules(timeline, rules_dir)
    assert len(findings) == 1
    assert "Good" in findings[0].title
