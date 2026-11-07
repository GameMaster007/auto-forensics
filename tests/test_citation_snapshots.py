"""The claim reader and the evidence hash must inspect the same captured bytes."""
from __future__ import annotations

import csv
import hashlib
import io
import json

import pytest

import auto_forensics.security as security
import auto_forensics.verifier as verifier
from auto_forensics.models import Citation, Finding


@pytest.mark.parametrize("kind", ["text", "csv", "json", "jsonl", "structured", "binary"])
def test_replacement_after_hash_cannot_supply_a_new_claim(tmp_path, monkeypatch, kind):
    old, claim = "An unrelated harmless record", "Credentials were stolen"
    suffix = {"text": ".txt", "csv": ".csv", "json": ".json", "jsonl": ".jsonl", "structured": ".raw", "binary": ".bin"}[kind]
    path = tmp_path / "host" / ("events" + suffix)
    path.parent.mkdir()

    def encode(text):
        if kind == "csv":
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer)
            writer.writerow(["description"])
            writer.writerow([text])
            return buffer.getvalue().encode()
        if kind in {"json", "jsonl"}:
            return (json.dumps({"description": text}) + "\n").encode()
        return text.encode()

    path.write_bytes(encode(old))
    real_sha256 = hashlib.sha256
    digest = real_sha256(path.read_bytes()).hexdigest()
    row = None if kind == "binary" else 2 if kind == "csv" else 1
    citation = Citation("event", "host/" + path.name, digest, row=row, offset=0 if kind == "binary" else None)
    finding = Finding("claim", "Claim", "high", 0.9, "credential-access", evidence=[claim], citations=[citation])
    replacements = []

    class ReplaceAfterHash:
        def __init__(self, data=b""):
            self.digest = real_sha256(data)

        def update(self, data):
            self.digest.update(data)

        def hexdigest(self):
            value = self.digest.hexdigest()
            path.write_bytes(encode(claim))
            replacements.append(True)
            return value

    if kind == "structured":
        monkeypatch.setattr(verifier, "_read_structured_record", lambda snapshot, row: snapshot.read_text())
    monkeypatch.setattr(security.hashlib, "sha256", ReplaceAfterHash)
    kept, verdicts = verifier.verify_findings([finding], tmp_path)
    assert replacements and claim in path.read_text()
    assert real_sha256(path.read_bytes()).hexdigest() != digest
    assert kept == [] and verdicts[0].verdict == "rejected"


@pytest.mark.parametrize("kind", ["directory", "fifo", "symlink"])
def test_evidence_capture_refuses_nonregular_sources_without_opening_a_pipe(tmp_path, kind):
    import os

    path = tmp_path / "source"
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("Named pipes are unavailable")
        os.mkfifo(path)
    else:
        target = tmp_path / "actual"
        target.write_bytes(b"data")
        path.symlink_to(target)
    with pytest.raises(security.SecurityError):
        security.capture_regular_evidence(path, tmp_path)


def test_binary_capture_retains_exact_window_across_streaming_chunk_boundaries(tmp_path):
    path = tmp_path / "binary.bin"
    data = b"a" * (1024 * 1024 - 3) + b"Located binary evidence" + b"z" * (1024 * 1024)
    path.write_bytes(data)
    start = data.index(b"Located")
    digest, window = security.capture_regular_evidence(path, tmp_path, start=start, window_bytes=21)
    assert digest == hashlib.sha256(data).hexdigest()
    assert window == data[start:start + 21]
    assert len(window) == 21


def test_text_snapshot_size_bound_is_enforced_before_copying(tmp_path):
    path, destination = tmp_path / "text.txt", tmp_path / "capture.txt"
    path.write_bytes(b"12345")
    with pytest.raises(security.SecurityError, match="size limit"):
        security.capture_regular_evidence(path, tmp_path, destination=destination, max_bytes=4)
    assert not destination.exists()
