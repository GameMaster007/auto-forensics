"""Multi-analyst collaboration system for Auto Forensics.

Provides case-level comments, activity feeds, analyst assignments,
and case locking functionality.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Comment:
    """A comment on a case or entity."""
    comment_id: str
    case_id: str
    entity_type: str  # 'case', 'finding', 'timeline', 'artifact'
    entity_id: str
    author: str
    content: str
    content_html: str
    parent_id: str | None
    mentions: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "comment_id": self.comment_id,
            "case_id": self.case_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "author": self.author,
            "content": self.content,
            "content_html": self.content_html,
            "parent_id": self.parent_id,
            "mentions": self.mentions,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(slots=True)
class ActivityEvent:
    """An activity event in the audit trail."""
    event_id: str
    case_id: str
    event_type: str  # 'comment_added', 'case_locked', 'analysis_complete', etc.
    actor: str
    description: str
    entity_type: str | None
    entity_id: str | None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "event_type": self.event_type,
            "actor": self.actor,
            "description": self.description,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class AnalystAssignment:
    """Assignment of a case to an analyst."""
    assignment_id: str
    case_id: str
    analyst: str
    assigned_by: str
    role: str  # 'analyst', 'lead', 'reviewer'
    status: str  # 'active', 'completed', 'removed'
    assigned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "assignment_id": self.assignment_id,
            "case_id": self.case_id,
            "analyst": self.analyst,
            "assigned_by": self.assigned_by,
            "role": self.role,
            "status": self.status,
            "assigned_at": self.assigned_at,
            "updated_at": self.updated_at,
        }


@dataclass(slots=True)
class CaseLock:
    """Lock on a case for exclusive access."""
    lock_id: str
    case_id: str
    locked_by: str
    locked_at: str
    expires_at: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "lock_id": self.lock_id,
            "case_id": self.case_id,
            "locked_by": self.locked_by,
            "locked_at": self.locked_at,
            "expires_at": self.expires_at,
            "reason": self.reason,
        }

    def is_expired(self) -> bool:
        """Check if lock has expired."""
        try:
            expires = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > expires
        except (ValueError, TypeError):
            return True


class CollaborationService:
    """Service for managing collaboration features."""

    def __init__(self, database: Any) -> None:
        """Initialize with database backend."""
        self.db = database

    # --- Comments ---

    def create_comment(
        self,
        case_id: str,
        entity_type: str,
        entity_id: str,
        author: str,
        content: str,
        parent_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a new comment.

        Args:
            case_id: Case identifier.
            entity_type: Type of entity being commented on.
            entity_id: Entity identifier.
            author: Comment author.
            content: Comment content (markdown).
            parent_id: Parent comment ID for threaded replies.

        Returns:
            Created comment as dictionary.
        """
        comment_id = hashlib.sha256(
            f"{case_id}:{entity_type}:{entity_id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        # Extract mentions (@username)
        mentions = self._extract_mentions(content)

        # Convert markdown to HTML (basic)
        content_html = self._markdown_to_html(content)

        comment = Comment(
            comment_id=comment_id,
            case_id=case_id,
            entity_type=entity_type,
            entity_id=entity_id,
            author=author,
            content=content,
            content_html=content_html,
            parent_id=parent_id,
            mentions=mentions,
        )

        self.db.save_comment(comment)

        # Log activity
        self._log_activity(
            case_id=case_id,
            event_type="comment_added",
            actor=author,
            description=f"Added comment on {entity_type}",
            entity_type=entity_type,
            entity_id=entity_id,
        )

        return comment.to_dict()

    def get_comments(
        self,
        case_id: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get comments for a case or entity.

        Args:
            case_id: Case identifier.
            entity_type: Optional entity type filter.
            entity_id: Optional entity ID filter.
            limit: Maximum comments to return.

        Returns:
            List of comment dictionaries.
        """
        return self.db.list_comments(case_id, entity_type, entity_id, limit)

    def get_comment_thread(self, comment_id: str) -> dict[str, Any] | None:
        """Get a comment and its replies.

        Args:
            comment_id: Comment ID.

        Returns:
            Comment with replies, or None if not found.
        """
        comment = self.db.get_comment(comment_id)
        if not comment:
            return None

        # Get replies
        replies = self.db.get_comment_replies(comment_id)
        comment["replies"] = replies

        return comment

    def update_comment(self, comment_id: str, content: str) -> dict[str, Any] | None:
        """Update a comment.

        Args:
            comment_id: Comment ID.
            content: New content.

        Returns:
            Updated comment, or None if not found.
        """
        comment = self.db.get_comment(comment_id)
        if not comment:
            return None

        mentions = self._extract_mentions(content)
        content_html = self._markdown_to_html(content)

        self.db.update_comment(comment_id, {
            "content": content,
            "content_html": content_html,
            "mentions": mentions,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

        return self.db.get_comment(comment_id)

    def delete_comment(self, comment_id: str) -> bool:
        """Delete a comment.

        Args:
            comment_id: Comment ID.

        Returns:
            True if deleted.
        """
        return self.db.delete_comment(comment_id)

    def _extract_mentions(self, content: str) -> list[str]:
        """Extract @mentions from content."""
        pattern = r"@([a-zA-Z0-9_]+)"
        return re.findall(pattern, content)

    def _markdown_to_html(self, content: str) -> str:
        """Convert markdown to HTML (basic implementation)."""
        # Escape HTML
        content = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Bold: **text** or __text__
        content = re.sub(r"\\*\\*(.+?)\\*\\*", r"<strong>\\1</strong>", content)
        content = re.sub(r"__(.+?)__", r"<strong>\\1</strong>", content)

        # Italic: *text* or _text_
        content = re.sub(r"\\*(.+?)\\*", r"<em>\\1</em>", content)
        content = re.sub(r"_(.+?)_", r"<em>\\1</em>", content)

        # Code: `text`
        content = re.sub(r"`(.+?)`", r"<code>\\1</code>", content)

        # Links: [text](url)
        content = re.sub(
            r"\\[([^\\]]+)\\]\\(([^\\)]+)\\)",
            r'<a href="\\2" target="_blank">\\1</a>',
            content,
        )

        # Line breaks
        content = content.replace("\\n", "<br>")

        return content

    # --- Activity Feed ---

    def _log_activity(
        self,
        case_id: str,
        event_type: str,
        actor: str,
        description: str,
        entity_type: str | None = None,
        entity_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log an activity event."""
        event = ActivityEvent(
            event_id=hashlib.sha256(
                f"{case_id}:{event_type}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16],
            case_id=case_id,
            event_type=event_type,
            actor=actor,
            description=description,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata=metadata or {},
        )

        try:
            self.db.save_activity_event(event)
        except Exception as e:
            logger.error("Failed to log activity: %s", e)

    def get_activity_feed(
        self,
        case_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get activity feed.

        Args:
            case_id: Optional case filter.
            limit: Maximum events.

        Returns:
            List of activity events.
        """
        return self.db.list_activity_events(case_id, limit=limit)

    # --- Assignments ---

    def assign_case(
        self,
        case_id: str,
        analyst: str,
        assigned_by: str,
        role: str = "analyst",
    ) -> dict[str, Any]:
        """Assign a case to an analyst.

        Args:
            case_id: Case identifier.
            analyst: Analyst username.
            assigned_by: User making the assignment.
            role: Analyst role (analyst/lead/reviewer).

        Returns:
            Assignment dictionary.
        """
        assignment_id = hashlib.sha256(
            f"{case_id}:{analyst}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        assignment = AnalystAssignment(
            assignment_id=assignment_id,
            case_id=case_id,
            analyst=analyst,
            assigned_by=assigned_by,
            role=role,
            status="active",
        )

        self.db.save_assignment(assignment)

        # Log activity
        self._log_activity(
            case_id=case_id,
            event_type="case_assigned",
            actor=assigned_by,
            description=f"Assigned {analyst} as {role}",
            metadata={"analyst": analyst, "role": role},
        )

        return assignment.to_dict()

    def get_case_assignments(self, case_id: str) -> list[dict[str, Any]]:
        """Get active assignments for a case.

        Args:
            case_id: Case identifier.

        Returns:
            List of assignments.
        """
        return self.db.list_assignments(case_id, status="active")

    def remove_assignment(self, assignment_id: str) -> bool:
        """Remove an assignment.

        Args:
            assignment_id: Assignment ID.

        Returns:
            True if removed.
        """
        assignment = self.db.get_assignment(assignment_id)
        if not assignment:
            return False

        self.db.update_assignment(assignment_id, {
            "status": "removed",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })

        # Log activity
        self._log_activity(
            case_id=assignment["case_id"],
            event_type="assignment_removed",
            actor="system",
            description=f"Removed assignment for {assignment['analyst']}",
        )

        return True

    # --- Case Locking ---

    def lock_case(
        self,
        case_id: str,
        locked_by: str,
        timeout_minutes: int = 30,
        reason: str = "",
    ) -> dict[str, Any]:
        """Lock a case for exclusive access.

        Args:
            case_id: Case identifier.
            locked_by: User locking the case.
            timeout_minutes: Lock timeout.
            reason: Lock reason.

        Returns:
            Lock dictionary.

        Raises:
            ValueError: If case is already locked by another user.
        """
        # Check existing lock
        existing = self.db.get_case_lock(case_id)
        if existing:
            existing_lock = CaseLock(**existing)
            if not existing_lock.is_expired() and existing_lock.locked_by != locked_by:
                raise ValueError(
                    f"Case is locked by {existing_lock.locked_by} until "
                    f"{existing_lock.expires_at}"
                )

        lock_id = hashlib.sha256(
            f"{case_id}:{locked_by}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        now = datetime.now(timezone.utc)
        expires = now.isoformat().replace("+00:00", "Z")
        # Add timeout (simple string manipulation for ISO format)
        from datetime import timedelta
        expires_dt = now + timedelta(minutes=timeout_minutes)
        expires = expires_dt.isoformat().replace("+00:00", "Z")

        lock = CaseLock(
            lock_id=lock_id,
            case_id=case_id,
            locked_by=locked_by,
            locked_at=now.isoformat().replace("+00:00", "Z"),
            expires_at=expires,
            reason=reason,
        )

        self.db.save_case_lock(lock)

        # Log activity
        self._log_activity(
            case_id=case_id,
            event_type="case_locked",
            actor=locked_by,
            description=f"Locked case for {timeout_minutes} minutes",
            metadata={"reason": reason, "expires": expires},
        )

        return lock.to_dict()

    def unlock_case(self, case_id: str, user: str) -> bool:
        """Unlock a case.

        Args:
            case_id: Case identifier.
            user: User attempting unlock.

        Returns:
            True if unlocked.

        Raises:
            ValueError: If user doesn't own the lock.
        """
        lock = self.db.get_case_lock(case_id)
        if not lock:
            return False

        if lock["locked_by"] != user:
            raise ValueError(f"Case locked by {lock['locked_by']}, not you")

        self.db.delete_case_lock(case_id)

        # Log activity
        self._log_activity(
            case_id=case_id,
            event_type="case_unlocked",
            actor=user,
            description="Unlocked case",
        )

        return True

    def get_case_lock(self, case_id: str) -> dict[str, Any] | None:
        """Get current lock on a case.

        Args:
            case_id: Case identifier.

        Returns:
            Lock dict, or None if not locked.
        """
        lock = self.db.get_case_lock(case_id)
        if lock:
            lock_obj = CaseLock(**lock)
            if lock_obj.is_expired():
                # Auto-expire
                self.db.delete_case_lock(case_id)
                return None
        return lock

    def extend_lock(
        self,
        case_id: str,
        user: str,
        additional_minutes: int = 30,
    ) -> dict[str, Any] | None:
        """Extend a case lock.

        Args:
            case_id: Case identifier.
            user: User extending the lock.
            additional_minutes: Time to add.

        Returns:
            Updated lock, or None.
        """
        lock = self.db.get_case_lock(case_id)
        if not lock or lock["locked_by"] != user:
            return None

        from datetime import timedelta
        current_expires = datetime.fromisoformat(lock["expires_at"].replace("Z", "+00:00"))
        new_expires = (current_expires + timedelta(minutes=additional_minutes)).isoformat()
        lock["expires_at"] = new_expires.replace("+00:00", "Z")

        self.db.update_case_lock(case_id, {"expires_at": lock["expires_at"]})

        return lock
