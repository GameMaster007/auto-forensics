"""Rules that decide whether a drafted finding may be shown.

A finding survives the citation check only when each citation it keeps
matches an artifact this run actually ingested. That check is on the
pointer (artifact id and SHA-256). The verifier in ``verifier.py`` is
the later pass that re-reads the row.
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
    source_file = path.name
    if root is not None:
        try:
            source_file = str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            source_file = path.name
    return Citation(
        artifact_id=f"file-{digest[:16]}",
        source_file=source_file,
        sha256=digest,
        offset=0,
    )


def catalog_key(citation: Citation) -> tuple[str, str, int | None, int | None]:
    """Identity of one pointer, including the row or offset."""
    return (citation.artifact_id, citation.sha256.lower(), citation.row, citation.offset)


def catalog_from_citations(
    citations: list[Citation],
) -> dict[tuple[str, str, int | None, int | None], Citation]:
    """Index complete citations by artifact id, hash, row, and offset.

    Two records in one file can share an artifact id. They stay as two
    catalog entries. A later record does not replace an earlier row.
    """
    catalog: dict[tuple[str, str, int | None, int | None], Citation] = {}
    for citation in citations:
        if not citation.is_complete():
            continue
        catalog[catalog_key(citation)] = citation
    return catalog


def bind_citations(
    finding: Finding,
    catalog: dict[tuple[str, str, int | None, int | None], Citation],
) -> Finding:
    """Replace a finding's citations with the catalog entries they match.

    The model may copy an id, but the row and path stored on the finding
    are the ones this process computed. A citation that names a different
    row is removed rather than rewritten onto another record.
    """
    bound: list[Citation] = []
    seen: set[tuple[str, str, int | None, int | None]] = set()
    for citation in finding.citations:
        key = catalog_key(citation)
        match = catalog.get(key)
        if match is None or key in seen:
            continue
        seen.add(key)
        bound.append(match)
    finding.citations = bound
    return finding


def drop_uncited(
    findings: list[Finding],
    catalog: dict[tuple[str, str, int | None, int | None], Citation],
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
