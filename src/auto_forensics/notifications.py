"""Notification system for Auto Forensics collaboration.

Handles user notifications for mentions, assignments, and activity.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Notification:
    """A user notification."""
    notification_id: str
    recipient: str
    notification_type: str  # 'mention', 'assignment', 'case_update', etc.
    title: str
    message: str
    case_id: str | None
    entity_type: str | None
    entity_id: str | None
    read: bool = False
    read_at: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "notification_id": self.notification_id,
            "recipient": self.recipient,
            "notification_type": self.notification_type,
            "title": self.title,
            "message": self.message,
            "case_id": self.case_id,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "read": self.read,
            "read_at": self.read_at,
            "created_at": self.created_at,
        }


class NotificationService:
    """Service for managing user notifications."""

    def __init__(self, database: Any) -> None:
        """Initialize with database backend."""
        self.db = database

    def create_notification(
        self,
        recipient: str,
        notification_type: str,
        title: str,
        message: str,
        case_id: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
    ) -> dict[str, Any]:
        """Create a notification.

        Args:
            recipient: Username to notify.
            notification_type: Type of notification.
            title: Notification title.
            message: Notification message.
            case_id: Optional case ID.
            entity_type: Optional entity type.
            entity_id: Optional entity ID.

        Returns:
            Created notification.
        """
        notification_id = hashlib.sha256(
            f"{recipient}:{notification_type}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        notification = Notification(
            notification_id=notification_id,
            recipient=recipient,
            notification_type=notification_type,
            title=title,
            message=message,
            case_id=case_id,
            entity_type=entity_type,
            entity_id=entity_id,
        )

        self.db.save_notification(notification)

        return notification.to_dict()

    def get_notifications(
        self,
        recipient: str,
        unread_only: bool = False,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Get notifications for a user.

        Args:
            recipient: Username.
            unread_only: Only return unread notifications.
            limit: Maximum notifications.

        Returns:
            List of notifications.
        """
        return self.db.list_notifications(recipient, unread_only, limit)

    def get_notification_count(self, recipient: str) -> int:
        """Get unread notification count.

        Args:
            recipient: Username.

        Returns:
            Number of unread notifications.
        """
        return self.db.count_notifications(recipient, unread_only=True)

    def mark_read(self, notification_id: str) -> dict[str, Any] | None:
        """Mark a notification as read.

        Args:
            notification_id: Notification ID.

        Returns:
            Updated notification, or None.
        """
        notification = self.db.get_notification(notification_id)
        if not notification:
            return None

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self.db.update_notification(notification_id, {"read": True, "read_at": now})

        return self.db.get_notification(notification_id)

    def mark_all_read(self, recipient: str) -> int:
        """Mark all notifications as read.

        Args:
            recipient: Username.

        Returns:
            Number of notifications marked read.
        """
        return self.db.mark_all_notifications_read(recipient)

    # --- Automatic notifications ---

    def notify_mentions(
        self,
        content: str,
        author: str,
        case_id: str,
        entity_type: str,
        entity_id: str,
    ) -> list[dict[str, Any]]:
        """Notify users mentioned in content.

        Args:
            content: Text content.
            author: Content author (excluded from notifications).
            case_id: Case ID.
            entity_type: Entity type.
            entity_id: Entity ID.

        Returns:
            List of created notifications.
        """
        import re
        mentions = re.findall(r"@([a-zA-Z0-9_]+)", content)
        notifications = []

        for username in mentions:
            if username == author:
                continue

            notif = self.create_notification(
                recipient=username,
                notification_type="mention",
                title=f"Mentioned in {case_id}",
                message=f"{author} mentioned you in a comment",
                case_id=case_id,
                entity_type=entity_type,
                entity_id=entity_id,
            )
            notifications.append(notif)

        return notifications

    def notify_assignment(
        self,
        analyst: str,
        assigned_by: str,
        case_id: str,
        role: str,
    ) -> dict[str, Any]:
        """Notify analyst of case assignment.

        Args:
            analyst: Assigned analyst.
            assigned_by: User making assignment.
            case_id: Case ID.
            role: Assigned role.

        Returns:
            Created notification.
        """
        return self.create_notification(
            recipient=analyst,
            notification_type="assignment",
            title=f"Assigned to {case_id}",
            message=f"You were assigned as {role} by {assigned_by}",
            case_id=case_id,
            entity_type="case",
            entity_id=case_id,
        )

    def notify_case_update(
        self,
        case_id: str,
        update_type: str,
        description: str,
        recipients: list[str],
    ) -> list[dict[str, Any]]:
        """Notify users of case updates.

        Args:
            case_id: Case ID.
            update_type: Type of update.
            description: Update description.
            recipients: Users to notify.

        Returns:
            List of created notifications.
        """
        notifications = []
        for recipient in recipients:
            notif = self.create_notification(
                recipient=recipient,
                notification_type="case_update",
                title=f"Case update: {case_id}",
                message=f"{update_type}: {description}",
                case_id=case_id,
                entity_type="case",
                entity_id=case_id,
            )
            notifications.append(notif)

        return notifications

    def notify_analysis_complete(
        self,
        case_id: str,
        findings_count: int,
        recipients: list[str],
    ) -> list[dict[str, Any]]:
        """Notify users when analysis completes.

        Args:
            case_id: Case ID.
            findings_count: Number of findings.
            recipients: Users to notify.

        Returns:
            List of created notifications.
        """
        notifications = []
        for recipient in recipients:
            notif = self.create_notification(
                recipient=recipient,
                notification_type="analysis_complete",
                title=f"Analysis complete: {case_id}",
                message=f"Analysis found {findings_count} findings",
                case_id=case_id,
                entity_type="case",
                entity_id=case_id,
            )
            notifications.append(notif)

        return notifications
