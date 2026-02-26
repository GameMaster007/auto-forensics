"""Tests for disk_image module."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


def test_is_disk_image_by_extension(tmp_path):
    from auto_forensics.disk_image import is_disk_image

    for ext in (".e01", ".dd", ".img", ".raw", ".vmdk", ".vhd", ".vhdx", ".aff"):
        p = tmp_path / f"sample{ext}"
        p.write_bytes(b"\x00" * 8)
        assert is_disk_image(p), f"Expected is_disk_image() True for {ext}"


def test_is_disk_image_rejects_zip(tmp_path):
    from auto_forensics.disk_image import is_disk_image

    p = tmp_path / "archive.zip"
    p.write_bytes(b"PK\x03\x04" + b"\x00" * 4)
    assert is_disk_image(p) is False


def test_detect_image_format_vhd(tmp_path):
    from auto_forensics.disk_image import detect_image_format

    p = tmp_path / "disk.vhd"
    p.write_bytes(b"\x00")
    assert detect_image_format(p) == "vhd"


def test_detect_image_format_vhdx(tmp_path):
    from auto_forensics.disk_image import detect_image_format

    p = tmp_path / "disk.vhdx"
    p.write_bytes(b"\x00")
    assert detect_image_format(p) == "vhdx"


def test_copy_artifacts_from_volume_copies_matching(tmp_path):
    from auto_forensics.disk_image import copy_artifacts_from_volume

    volume = tmp_path / "volume"
    staging = tmp_path / "staging"
    volume.mkdir()
    staging.mkdir()

    # Create matching EVTX
    evtx_dir = volume / "Windows" / "System32" / "winevt" / "Logs"
    evtx_dir.mkdir(parents=True)
    evtx = evtx_dir / "Security.evtx"
    evtx.write_bytes(b"ELFFILE" + b"\x00" * 100)

    copied = copy_artifacts_from_volume(volume, staging, max_file_size_bytes=1024 * 1024)
    assert any(p.name == "Security.evtx" for p in copied)


def test_copy_artifacts_oversized_skipped(tmp_path):
    from auto_forensics.disk_image import copy_artifacts_from_volume

    volume = tmp_path / "volume"
    staging = tmp_path / "staging"
    volume.mkdir()
    staging.mkdir()

    big = volume / "big.evtx"
    big.write_bytes(b"X" * 10)  # only 10 bytes, but we set limit to 5

    copied = copy_artifacts_from_volume(volume, staging, max_file_size_bytes=5)
    assert not any(p.name == "big.evtx" for p in copied)


def test_copy_artifacts_lnk_renamed_to_bin(tmp_path):
    from auto_forensics.disk_image import copy_artifacts_from_volume

    volume = tmp_path / "volume"
    staging = tmp_path / "staging"
    (volume / "Desktop").mkdir(parents=True)
    staging.mkdir()

    lnk = volume / "Desktop" / "shortcut.lnk"
    lnk.write_bytes(b"L\x00\x00\x00" + b"\x00" * 100)

    copied = copy_artifacts_from_volume(volume, staging)
    dest_names = {p.name for p in copied}
    assert "shortcut.bin" in dest_names
    assert "shortcut.lnk" not in dest_names


def test_extract_image_to_staging_unmounted(tmp_path):
    """When ImageMounter returns None, mounted should be False."""
    from auto_forensics.disk_image import extract_image_to_staging

    image = tmp_path / "disk.e01"
    image.write_bytes(b"EVF" + b"\x00" * 20)
    staging = tmp_path / "out"

    with patch("auto_forensics.disk_image.ImageMounter") as MockMounter:
        mock_instance = MagicMock()
        mock_instance.__enter__ = MagicMock(return_value=None)
        mock_instance.__exit__ = MagicMock(return_value=False)
        MockMounter.return_value = mock_instance

        result = extract_image_to_staging(image, staging)

    assert result["mounted"] is False
    assert result["artifacts_copied"] == 0
    assert result["error"] is not None
