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

CitationKey = tuple[str, str, str, int | None, int | None]
CitationIdentity = tuple[str, str, int | None, int | None]


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
    """Point to the representative keyword, or the whole file at offset 0."""
    digest = binary.sha256.lower()
    offset = 0
    if binary.string_hits:
        offsets = [match.offset for match in binary.string_matches if match.keyword == binary.string_hits[0]]
        if offsets:
            offset = min(offsets)
    return Citation(
        artifact_id=f"bin-{digest[:16]}",
        source_file=Path(binary.path).name if Path(binary.path).is_absolute() else str(Path(binary.path)),
        sha256=digest,
        offset=offset,
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


def catalog_key(citation: Citation) -> CitationKey:
    """Identity of one pointer, including its source path and location."""
    return (citation.artifact_id, citation.sha256.lower(), citation.source_file, citation.row, citation.offset)


def _identity(citation: Citation) -> CitationIdentity:
    return (citation.artifact_id, citation.sha256.lower(), citation.row, citation.offset)


def catalog_from_citations(
    citations: list[Citation],
) -> dict[CitationKey, Citation]:
    """Index complete citations by artifact id, hash, source, row, and offset.

    Two records in one file can share an artifact id. They stay as two
    catalog entries. A later record does not replace an earlier row.
    Identical content from separate source paths also stays separate.
    """
    catalog: dict[CitationKey, Citation] = {}
    for citation in citations:
        if not citation.is_complete():
            continue
        catalog[catalog_key(citation)] = citation
    return catalog


def bind_citations(
    finding: Finding,
    catalog: dict[CitationKey, Citation],
    *, identities: dict[CitationIdentity, list[Citation]] | None = None,
) -> Finding:
    """Replace a finding's citations with the catalog entries they match.

    The model may copy an id, but the row and path stored on the finding
    are the ones this process computed. A citation that names a different
    row is removed rather than rewritten onto another record. A copied
    path is corrected only when its artifact identity is unambiguous.
    """
    if identities is None:
        identities = _by_identity(catalog)
    bound: list[Citation] = []
    seen: set[CitationKey] = set()
    for citation in finding.citations:
        key = catalog_key(citation)
        match = catalog.get(key)
        if match is None:
            candidates = identities.get(_identity(citation), [])
            match = candidates[0] if len(candidates) == 1 else None
        if match is None or catalog_key(match) in seen:
            continue
        seen.add(catalog_key(match))
        bound.append(match)
    finding.citations = bound
    return finding


def drop_uncited(
    findings: list[Finding],
    catalog: dict[CitationKey, Citation],
) -> tuple[list[Finding], int]:
    """Keep findings that still have a catalog citation. Count the rest."""
    kept: list[Finding] = []
    dropped = 0
    identities = _by_identity(catalog)
    for finding in findings:
        bind_citations(finding, catalog, identities=identities)
        if finding.citations:
            kept.append(finding)
        else:
            dropped += 1
    return kept, dropped


def _by_identity(catalog: dict[CitationKey, Citation]) -> dict[CitationIdentity, list[Citation]]:
    index: dict[CitationIdentity, list[Citation]] = {}
    for citation in catalog.values():
        index.setdefault(_identity(citation), []).append(citation)
    return index


def _as_int(value: object) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None
