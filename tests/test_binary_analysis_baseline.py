from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from auto_forensics.binary_analysis import analyze_binary, _streaming_analysis

def test_streaming_analysis(tmp_path: Path):
    f = tmp_path / "test.bin"
    # 'hello'
    f.write_bytes(b"hello")
    sha256, md5, entropy, size, raw = _streaming_analysis(f)
    assert size == 5
    assert entropy == 1.9219
    assert raw == b"hello"
    assert sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

def test_analyze_binary_reads_file_minimally(tmp_path: Path):
    f = tmp_path / "test.exe"
    f.write_bytes(b"MZ" + b"\x00" * 100 + b"powershell" + b"\xff" * 100)
    
    with patch("pathlib.Path.open", side_effect=Path.open, autospec=True) as mock_open:
        feat = analyze_binary(f)
        assert feat.sha256 is not None
        assert "powershell" in feat.string_hits
        
        # 1. _streaming_analysis
        # 2. _extract_pe_import_hints (pefile.PE opens it, IF installed)
        # So it should be 1 or 2.
        assert mock_open.call_count in {1, 2}
        print(f"Open call count: {mock_open.call_count}")

def test_analyze_binary_behavior(tmp_path: Path):
    f = tmp_path / "suspicious.exe"
    # Small file, high entropy-ish, suspicious string
    content = b"MZ" + b"\x00" * 10 + b"powershell" + b"\x01\x02\x03\x04\x05\x06\x07\x08"
    f.write_bytes(content)
    
    feat = analyze_binary(f)
    assert feat.path == str(f)
    assert feat.size_bytes == len(content)
    assert "powershell" in feat.string_hits
    assert feat.suspicious_score > 0
    assert any("Small executable size" in r for r in feat.rationale)
