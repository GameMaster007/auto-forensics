from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")


class SecurityError(ValueError):
    pass


@dataclass(slots=True)
class SecurityPolicy:
    max_file_size_bytes: int = 100 * 1024 * 1024
    max_total_files: int = 200_000
    max_text_bytes: int = 4 * 1024 * 1024
    follow_symlinks: bool = False


def validate_case_id(case_id: str) -> str:
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise SecurityError(
            "Invalid case_id. Use 2-64 characters: letters, numbers, dot, underscore, hyphen."
        )
    return case_id


def confine_path(root: Path, candidate: Path) -> Path:
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise SecurityError(f"Path escapes allowed root: {candidate}") from exc
    return candidate_resolved


def is_supported_artifact(path: Path) -> bool:
    suffix = path.suffix.lower()
    basename = path.name.upper()
    if basename in {"SOFTWARE", "SYSTEM", "SAM", "SECURITY", "NTUSER.DAT", "USRCLASS.DAT", "$MFT"}:
        return True
    return suffix in {
        ".json",
        ".csv",
        ".txt",
        ".log",
        ".evtx",
        ".pcap",
        ".pcapng",
        ".pf",
        ".mft",
        ".hiv",
        ".hive",
        ".raw",
        ".dmp",
        ".mem",
        ".exe",
        ".dll",
        ".sys",
        ".bin",
        ".sqlite",
        ".db",
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_limited_text(path: Path, max_bytes: int) -> str:
    with path.open("rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise SecurityError(f"File exceeds maximum text size: {path}")
    return data.decode("utf-8", errors="replace")


def walk_case_directory(root: Path, policy: SecurityPolicy, filter_func=is_supported_artifact):
    """Efficiently walk a directory while respecting security policy."""
    root_resolved = root.resolve()
    stack = [root_resolved]
    visited_dirs: set[Path] = {root_resolved}
    yielded_files = 0
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                # Sort entries for deterministic behavior across platforms.
                for entry in sorted(it, key=lambda e: e.name):
                    src = Path(entry.path)
                    try:
                        # Check for symlink first, before any other operation
                        is_symlink = entry.is_symlink()
                        if is_symlink and not policy.follow_symlinks:
                            continue

                        # For symlinks that we do follow, use lstat to check
                        # the link itself, then verify target is within bounds
                        if is_symlink and policy.follow_symlinks:
                            try:
                                link_target = src.readlink()
                                # Reject absolute symlinks that point outside root
                                if link_target.is_absolute():
                                    target_resolved = (current / link_target).resolve()
                                    try:
                                        target_resolved.relative_to(root_resolved)
                                    except ValueError:
                                        continue  # Symlink points outside root
                                else:
                                    # Relative symlinks are OK, resolve relative
                                    # to current directory
                                    target_resolved = (current / link_target).resolve()
                                    target_resolved.relative_to(root_resolved)
                            except (OSError, ValueError):
                                continue  # Invalid symlink or escapes root

                        # Now confine the path
                        src = confine_path(root_resolved, src)
                    except SecurityError:
                        continue
                    try:

                        if entry.is_dir(
                            follow_symlinks=policy.follow_symlinks
                        ):
                            if src in visited_dirs:
                                continue
                            visited_dirs.add(src)
                            stack.append(src)
                            continue

                        if not entry.is_file(
                            follow_symlinks=policy.follow_symlinks
                        ):
                            continue

                        if filter_func and not filter_func(src):
                            continue

                        size_bytes = entry.stat(
                            follow_symlinks=policy.follow_symlinks
                        ).st_size
                        if size_bytes > policy.max_file_size_bytes:
                            continue

                        yielded_files += 1
                        if yielded_files > policy.max_total_files:
                            raise SecurityError(
                                "Maximum file count exceeded during directory walk."
                            )

                        yield src
                    except OSError:
                        continue
        except OSError:
            continue


def validate_webhook_url(url: str, require_https: bool = True) -> str:
    """Validate webhook URL to prevent SSRF attacks.

    Args:
        url: The webhook URL to validate.
        require_https: If True, only HTTPS URLs are allowed.

    Returns:
        The validated URL.

    Raises:
        SecurityError: If URL is invalid or points to internal addresses.
    """
    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise SecurityError(f"Invalid URL: {url}") from exc

    if not parsed.scheme or not parsed.hostname:
        raise SecurityError(f"Invalid URL - missing scheme or hostname: {url}")

    # Require HTTPS in production
    if require_https and parsed.scheme != "https":
        raise SecurityError(
            f"HTTPS required for webhook URL. Invalid URL: {url}"
        )

    hostname = parsed.hostname.lower()

    # Block internal/private IP addresses
    blocked_prefixes = (
        "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
        "172.29.", "172.30.", "172.31.", "0.", "169.254.",
    )
    if any(hostname.startswith(p) for p in blocked_prefixes):
        raise SecurityError(
            f"Webhook URL points to internal address: {hostname}"
        )

    # Block localhost variants
    if hostname in ("localhost", "0.0.0.0", "::1", "::"):
        raise SecurityError(
            f"Webhook URL points to internal address: {hostname}"
        )

    # Try to parse as IP to catch other private ranges
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            raise SecurityError(
                f"Webhook URL points to internal address: {hostname}"
            )
    except ValueError:
        # Not an IP address, that's fine
        pass

    return url
