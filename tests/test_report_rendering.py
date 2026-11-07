"""Evidence is readable without scripts and cannot become dashboard markup."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

from auto_forensics.models import IOC, CaseReport, Finding, TimelineEvent
from auto_forensics.pipeline import _to_html


class _VisibleReport(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script = False
        self.tags: list[str] = []
        self.visible: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "script":
            self.in_script = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if not self.in_script:
            self.visible.append(data)


def test_report_contains_escaped_evidence_before_any_script_runs():
    attack = '<b id="evidence-markup">quoted & evidence</b>'
    report = CaseReport(
        "static-report", "2026-11-07T00:00:00Z", [],
        [Finding("f1", attack, "high", 0.9, "execution", review_status="rejected", verification="not verified")],
        [TimelineEvent("2026-11-07T00:00:00Z", "host-a", "execution", attack)],
        {"total_findings": 1, "timeline_events": 1, "ioc_count": 1},
        iocs=[IOC("ioc1", "url", "https://example.test/Case?Q=1", sources=[attack])],
    )
    parsed = _VisibleReport()
    rendered = _to_html(report)
    parsed.feed(rendered)
    visible = " ".join(parsed.visible)
    assert visible.count(attack) == 3
    assert "https://example.test/Case?Q=1" in visible
    assert "analyst-rejected" in visible and "not verified" in visible
    assert "high" in visible and "host-a" in visible
    assert "b" not in parsed.tags
    assert '<table id="findings"><thead>' in rendered
    assert 'id="timelineToolbar" hidden' in rendered


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required for report JavaScript regression")
def test_interactive_report_summary_values_remain_text():
    attack = '<img src=x onerror="alert(1)">'
    report = CaseReport("summary-text", "2026-11-07T00:00:00Z", [], [], [], {
        key: attack for key in ("total_findings", "timeline_events", "ioc_count", "attack_technique_coverage")
    })
    script = re.search(r"<script>(.*?)</script>", _to_html(report), re.DOTALL)
    assert script is not None
    harness = r"""
const fs = require('fs');
const vm = require('vm');
const elements = new Map();
const document = {getElementById(id) {
  if (!elements.has(id)) elements.set(id, {innerHTML:'', addEventListener(){}});
  return elements.get(id);
}};
vm.runInNewContext(fs.readFileSync(0, 'utf8'), {document});
console.log(elements.get('kpis').innerHTML);
"""
    result = subprocess.run(["node", "-e", harness], input=script[1], capture_output=True, text=True, check=True, timeout=10)
    parsed = _VisibleReport()
    parsed.feed(result.stdout)
    assert "img" not in parsed.tags
    assert " ".join(parsed.visible).count(attack) == 4


@pytest.mark.skipif(shutil.which("node") is None, reason="Node is required for dashboard JavaScript regression")
def test_dashboard_treats_all_server_fields_as_text_and_avoids_inline_styles():
    script = Path(__file__).parents[1] / "src/auto_forensics/web/dashboard.js"
    harness = r"""
const fs = require('fs');
const vm = require('vm');
const elements = new Map();
const document = {getElementById(id) {
  if (!elements.has(id)) elements.set(id, {innerHTML:'', value:'', textContent:'', addEventListener(){}});
  return elements.get(id);
}};
const hostile = `<img src=x onerror="alert(1)"> & 'quoted'`;
const context = vm.createContext({document, hostile, fetch: async () => ({ok:true,text:async()=> '[]'}), setTimeout});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
vm.runInContext(`
renderCases([{case_id:hostile,status:hostile,updated_at:hostile}]);
renderTimeline([{timestamp:hostile,event_type:hostile,source:hostile,description:hostile}], '');
renderHeatmap([{timestamp:'2026-11-07T03:00:00Z'}]);
`, context);
console.log(JSON.stringify(Object.fromEntries(['cases','timeline','heatmap'].map(id=>[id, elements.get(id).innerHTML]))));
"""
    result = subprocess.run(["node", "-e", harness, str(script)], capture_output=True, text=True, check=True, timeout=10)
    rendered = json.loads(result.stdout)
    for target in ("cases", "timeline"):
        parsed = _VisibleReport()
        parsed.feed(rendered[target])
        assert "img" not in parsed.tags
        assert '<img src=x onerror="alert(1)">' in "".join(parsed.visible)
    assert 'style="' not in rendered["heatmap"]
    assert '<progress class="heat-bar" max="100" value="100"' in rendered["heatmap"]
