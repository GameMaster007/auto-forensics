"""Real Windows artefacts for tests, downloaded at test time from pinned GitHub commits.

Nothing here is stored in this repository. Each sample is fetched from a
fixed commit of a public test-data set, checked against a SHA-256, and
kept for the rest of the test session. A test that asks for a sample is
skipped when the machine is offline or the file no longer matches.

Sources:

* log2timeline/plaso ``test_data`` (Apache-2.0)
* mkorman90/regipy ``regipy_tests/data`` (MIT), xz-compressed hives

Set ``AUTO_FORENSICS_TEST_SAMPLES`` to a folder to keep the downloads
between test runs.
"""

from __future__ import annotations

import hashlib
import lzma
import os
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

PLASO = "https://raw.githubusercontent.com/log2timeline/plaso/f75784eea92ce1f946e822a675836da45d91309c/test_data/"
REGIPY = ("https://raw.githubusercontent.com/mkorman90/regipy/c6de929abc37d8315d1c31aba5e937db636f3303/"
          "regipy_tests/data/")
MAX_DOWNLOAD = 48 * 1024 * 1024
MAX_UNPACKED = 96 * 1024 * 1024

# name used by tests -> (base URL, path under it, SHA-256 of the downloaded bytes)
SAMPLES: dict[str, tuple[str, str, str]] = {
    # Registry hives. SYSTEM and SOFTWARE are from the same Windows 7 computer (WKS-WIN732BITA).
    "SYSTEM": (REGIPY, "SYSTEM.xz", "e19c910ff457a4ef81a3b4d7f6206ec8a7e8fa82b6e40a6c93e40699b02a52bb"),
    "SOFTWARE": (REGIPY, "SOFTWARE.xz", "e0db74a30c97c86c025255d5c12f3f1865c1df82cfb28484617c89c7c2793018"),
    "SYSTEM-WIN10": (REGIPY, "SYSTEM_WIN_10_1709.xz", "703357b4fabf145c01e1381fa8c4b11b512c9f276a54aba12dcf1f5a789b2cf8"),
    "NTUSER-BAGMRU": (REGIPY, "NTUSER_BAGMRU.DAT.xz", "53ee3905ba84da92034f2c430cb353fd7574a89e8c40e67f62211895b0559637"),
    "NTUSER-WIN7": (PLASO, "NTUSER-WIN7.DAT", "672abb15ae62fa8c002c5ee0a730cf83cd5f40706d5ffdec8f1179cf47a0bd03"),
    "NTUSER-XP": (PLASO, "NTUSER.DAT", "4a3232850f9677de96774b4de0020ac7f5e2efeb5e4576a200bb751d9e1c9d1d"),
    "NTUSER-CCLEANER": (PLASO, "NTUSER-CCLEANER.DAT", "3cab6fd2eaff4912b85c3a0cb86d243a3408ae5301b89a9c7e3b79fb2a69b2ad"),
    "SAM": (PLASO, "regf/SAM", "ce88f84842d5048550542126c1d9cc15ba7dea0486996dc1c814bf8a2d9351ea"),
    # Shortcuts and Jump Lists.
    "nero.lnk": (PLASO, "NeroInfoTool.lnk", "186fd33109985cccb41a5fcc4fdc9d53b71d8d286e1b65b74dd9ad065a863fbb"),
    "example.lnk": (PLASO, "example.lnk", "dd6dcad341a17c639522c36afba7f9fbca708997b7e678f83d9e72323d771c19"),
    "auto-win7.jump": (PLASO, "automaticDestinations-ms/1b4dd67f29cb1962.automaticDestinations-ms",
                       "003a1b2e449f1b8bd790ca6dc3b01378b2e835836b464556d70883a6eebcf414"),
    "auto-win10.jump": (PLASO, "automaticDestinations-ms/9d1f905ce5044aee.automaticDestinations-ms",
                        "6c59abb4bc79f1abf51cb836fe17b95066f4dfb1b91c61f13a22316bea1d0d9f"),
    "custom.jump": (PLASO, "customDestinations-ms/5afe4de1b92fc382.customDestinations-ms",
                    "c1c77214698293fcfd9fb4cae296a3faa88191092ff381e97fd947cb62bba217"),
    # Prefetch: XP (v17), Windows 7 (v23), Windows 8.1 (v26), Windows 10 (v30, compressed).
    "CMD.pf": (PLASO, "winprefetch/CMD.EXE-087B4001.pf",
               "93ec53e941b285d1d2a11e1224ab2d5c7a1b8ac493ab8dec407f518c5655ae75"),
    "PING.pf": (PLASO, "winprefetch/PING.EXE-B29F6629.pf",
                "cdb6e2de2b02808755aa2591708ebe155ee3483947e230f5fdd6870390fafd26"),
    "TASKHOST.pf": (PLASO, "winprefetch/TASKHOST.EXE-3AE259FC.pf",
                    "00178686d5e755e596ee164e78473eab3aba382541d0f67f93654ef84d4ed36b"),
    "NOTEPAD.pf": (PLASO, "winprefetch/NOTEPAD.EXE-D8414F97.pf",
                   "2eb257a375eda819c65e6b4e60dfb7b9c6691280e8cb40cec30d3e46ac96a50f"),
    "ONEDRIVE.pf": (PLASO, "winprefetch/ONEDRIVE.EXE-7E152375.pf",
                    "e9a5db11b673ba592a794a2bfeaa2aba95814d3004c32a76e4dc668789fa2424"),
    # Recycle Bin index files (Windows 7 and Windows 10 formats).
    "$II3DF3L.zip": (PLASO, "recycler/$II3DF3L.zip", "016d798595fe02bc19ee53511055a3ab3343a81a5ecc1301e606c5646b8b1ce8"),
    "$I103S5F.jpg": (PLASO, "recycler/$I103S5F.jpg", "23c233e261b9b496f547dfc7447050fbae452dffbdd135a43d1bad31bc7b0df9"),
    # Browser history.
    "chrome-History": (PLASO, "chrome/History", "c184fd5fdf72b75c26f8bb816619f04892e776ae6e2f5512f796d9807a12fbb3"),
    "chrome59-History": (PLASO, "chrome/History-59.0.3071.86",
                         "946338ebab6d11f7520e9fc3186e8834253e0182c06ca3b2ec1b0ccbe1207b69"),
    "firefox25-places": (PLASO, "firefox/firefox_25_places.sqlite",
                         "16038743834f96d0d0f30f28ffd7edc2af95ff09f4567bab90ed7a9099bb2afc"),
    "firefox118-places": (PLASO, "firefox/places118.sqlite",
                          "9c4fea060279998f12d1fdf850b7160a86636b4899fee72bcc96e2e6f7f71831"),
    "index.dat": (PLASO, "msiecf/History.IE5/index.dat",
                  "d54847adc8be889cb687bd7c60af50153d310eb3fc32a79d20c93eecb655bfc1"),
    "WebCacheV01.dat": (PLASO, "WebCacheV01.dat", "2713e7ff413c69659442c5dcb0f23f41230fa76bf760b8aeac0ffd430d10c83e"),
    # Other.
    "setupapi.dev.log": (PLASO, "setupapi.dev.log", "77518a7e8f825ef19323e2ab5ab83ad74ee93ae4c91c4a7ffca05930065ea013"),
    "gdrive-snapshot.db": (PLASO, "sqlite/snapshot.db",
                           "82324ff668dbf6ad97e2f85894cbdd729881464355006528c19bc4b50f1e5264"),
}

_session_dir: Path | None = None


def _cache_dir() -> Path:
    global _session_dir
    configured = os.environ.get("AUTO_FORENSICS_TEST_SAMPLES")
    if configured:
        folder = Path(configured)
        folder.mkdir(parents=True, exist_ok=True)
        return folder
    if _session_dir is None:
        _session_dir = Path(tempfile.mkdtemp(prefix="af-real-samples-"))
    return _session_dir


def sample(name: str) -> Path:
    """Path of a real artefact (downloaded once), or skip the calling test."""
    base, relative, digest = SAMPLES[name]
    target = _cache_dir() / digest[:16] / Path(relative).name.removesuffix(".xz")
    if target.is_file():
        return target
    marker = target.parent / "unavailable"
    if marker.is_file():
        pytest.skip(marker.read_text(encoding="utf-8"))
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(base + urllib.parse.quote(relative), timeout=60) as response:
            data = response.read(MAX_DOWNLOAD + 1)
    except OSError as exc:  # includes URLError, HTTPError and timeouts
        reason = f"offline: real sample {name} could not be downloaded ({type(exc).__name__})"
        marker.write_text(reason, encoding="utf-8")
        pytest.skip(reason)
    if len(data) > MAX_DOWNLOAD or hashlib.sha256(data).hexdigest() != digest:
        reason = f"real sample {name} changed upstream"
        marker.write_text(reason, encoding="utf-8")
        pytest.skip(reason)
    if relative.endswith(".xz"):
        data = lzma.LZMADecompressor().decompress(data, max_length=MAX_UNPACKED)
    temporary = target.with_suffix(target.suffix + ".part")
    temporary.write_bytes(data)
    temporary.replace(target)
    return target
