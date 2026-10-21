"""Rules that decide whether a drafted finding may be shown.

A finding survives only when each citation it keeps matches an artifact
this run actually ingested. The check is on the pointer (artifact id
and SHA-256). It does not re-read the row and decide whether the
sentence is true. That second check is the verifier, which is not
implemented yet.
"""

from __future__ import annotations

from pathlib import Path

from .models import ArtifactEvent, BinaryFeature, Citation, Finding
from .security import sha256_file


def citation_from_event(event: ArtifactEvent) -> Citation | None:
    """Build a citation from parser provenance, or return None."""
    digest = str(event.metadata.get("source_sha256") or "").lower()
    source_file = str(event.metadata.get("source_file") or "")
    citation = Citation(
        artifact_id=event.artifact_id,
        source_file=source_file,
        sha256=digest,
        row=_as_int(event.metadata.get("row")),
        offset=_as_int(event.metadata.get("offset")),
    )
    if not citation.is_complete():
        return None
    return citation


def citation_for_binary(binary: BinaryFeature) -> Citation:
    """Cite a whole file at byte offset 0.

    Binary triage does not yet point at the matching string inside the
    file. Offset 0 means "this file", which is the honest pointer until
    a later change records the matching offset.
    """
    digest = binary.sha256.lower()
    return Citation(
        artifact_id=f"bin-{digest[:16]}",
        source_file=Path(binary.path).name,
        sha256=digest,
        offset=0,
    )


def file_citation(path: Path, root: Path | None = None) -> Citation:
    """Cite a file that was hashed during this run, at offset 0."""
    digest = sha256_file(path).lower()
    if root is not None:
        source_file = str(path.resolve().relative_to(root.resolve()))
    else:
        source_file = path.name
    return Citation(
        artifact_id=f"file-{digest[:16]}",
        source_file=source_file,
        sha256=digest,
        offset=0,
    )


def catalog_from_citations(citations: list[Citation]) -> dict[tuple[str, str], Citation]:
    """Index complete citations by ``(artifact_id, sha256)``."""
    catalog: dict[tuple[str, str], Citation] = {}
    for citation in citations:
        if not citation.is_complete():
            continue
        catalog[(citation.artifact_id, citation.sha256.lower())] = citation
    return catalog


def bind_citations(finding: Finding, catalog: dict[tuple[str, str], Citation]) -> Finding:
    """Replace a finding's citations with the catalog entries they match.

    A model may copy an id, but the row and path stored on the finding
    are the ones this process computed. Citations that do not match the
    catalog are removed.
    """
    bound: list[Citation] = []
    seen: set[tuple[str, str]] = set()
    for citation in finding.citations:
        key = (citation.artifact_id, citation.sha256.lower())
        match = catalog.get(key)
        if match is None or key in seen:
            continue
        seen.add(key)
        bound.append(match)
    finding.citations = bound
    return finding


def drop_uncited(
    findings: list[Finding],
    catalog: dict[tuple[str, str], Citation],
) -> tuple[list[Finding], int]:
    """Keep findings that still have a catalog citation. Count the rest."""
    kept: list[Finding] = []
    dropped = 0
    for finding in findings:
        bind_citations(finding, catalog)
        if finding.citations:
            kept.append(finding)
        else:
            dropped += 1
    return kept, dropped


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None
