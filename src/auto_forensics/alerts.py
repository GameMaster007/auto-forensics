"""Alerting and notification system for case events.

Supports webhook, email, and console notifications
with configurable rules and severities.
"""

from __future__ import annotations

import json
import logging
import smtplib
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Severity levels for alerts."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertChannel(Enum):
    """Notification channels."""

    WEBHOOK = "webhook"
    EMAIL = "email"
    CONSOLE = "console"


@dataclass(slots=True)
class SMTPConfig:
    """SMTP configuration for email alerts."""

    host: str
    port: int = 587
    username: str | None = None
    password: str | None = None
    use_tls: bool = True
    from_addr: str = "alerts@auto-forensics.local"


@dataclass(slots=True)
class AlertRule:
    """A rule for triggering alerts."""

    rule_id: str
    name: str
    description: str = ""
    enabled: bool = True
    trigger_condition: dict[str, Any] = field(default_factory=dict)
    channels: list[AlertChannel] = field(
        default_factory=lambda: [AlertChannel.CONSOLE]
    )
    webhook_url: str | None = None
    email_recipients: list[str] = field(default_factory=list)
    smtp_config: SMTPConfig | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "trigger_condition": self.trigger_condition,
            "channels": [c.value for c in self.channels],
            "webhook_url": self.webhook_url,
            "email_recipients": self.email_recipients,
            "smtp_config": {
                "host": self.smtp_config.host,
                "port": self.smtp_config.port,
                "from_addr": self.smtp_config.from_addr,
            } if self.smtp_config else None,
        }


@dataclass(slots=True)
class Alert:
    """A triggered alert instance."""

    alert_id: str
    rule_id: str
    case_id: str
    severity: AlertSeverity
    message: str
    timestamp: str
    data: dict[str, Any] = field(default_factory=dict)
    sent_channels: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "case_id": self.case_id,
            "severity": self.severity.value,
            "message": self.message,
            "timestamp": self.timestamp,
            "data": self.data,
            "sent_channels": self.sent_channels,
        }


class AlertManager:
    """Manages alert rules and sends notifications."""

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules: list[AlertRule] = []
        self.rules_path = rules_path
        self._lock = threading.Lock()
        self._alert_history: list[Alert] = []
        self._max_history = 1000
        if rules_path and rules_path.exists():
            self.load_rules(rules_path)

    def load_rules(self, rules_path: Path | None = None) -> None:
        """Load alert rules from JSON file."""
        path = rules_path or self.rules_path
        if not path or not path.exists():
            logger.debug("No rules file found at %s", path)
            return
        try:
            with path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            rules_data = data.get("rules", [])
            with self._lock:
                self.rules = []
                for r in rules_data:
                    smtp = r.get("smtp_config")
                    smtp_config = SMTPConfig(
                        host=smtp.get("host", "localhost"),
                        port=smtp.get("port", 587),
                        username=smtp.get("username"),
                        password=smtp.get("password"),
                        use_tls=smtp.get("use_tls", True),
                        from_addr=smtp.get("from_addr", "alerts@localhost"),
                    ) if smtp else None
                    self.rules.append(AlertRule(
                        rule_id=str(r.get("rule_id", "")),
                        name=str(r.get("name", "")),
                        description=str(r.get("description", "")),
                        enabled=bool(r.get("enabled", True)),
                        trigger_condition=r.get(
                            "trigger_condition", {}
                        ),
                        channels=[
                            AlertChannel(c)
                            for c in r.get("channels", ["console"])
                        ],
                        webhook_url=r.get("webhook_url"),
                        email_recipients=r.get(
                            "email_recipients", []
                        ),
                        smtp_config=smtp_config,
                    ))
            logger.info("Loaded %d alert rules from %s", len(self.rules), path)
        except Exception as exc:
            logger.error("Failed to load rules: %s", exc)

    def save_rules(self, rules_path: Path | None = None) -> None:
        """Save alert rules to JSON file."""
        path = rules_path or self.rules_path
        if not path:
            logger.warning("No rules path configured")
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                data = {
                    "rules": [r.to_dict() for r in self.rules],
                }
            with path.open("w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            logger.info("Saved %d rules to %s", len(self.rules), path)
        except Exception as exc:
            logger.error("Failed to save rules: %s", exc)

    def add_rule(self, rule: AlertRule) -> None:
        """Add a new alert rule."""
        with self._lock:
            self.rules.append(rule)
        if self.rules_path:
            self.save_rules()

    def remove_rule(self, rule_id: str) -> bool:
        """Remove an alert rule by ID."""
        with self._lock:
            initial_len = len(self.rules)
            self.rules = [r for r in self.rules if r.rule_id != rule_id]
            removed = len(self.rules) < initial_len
        if removed and self.rules_path:
            self.save_rules()
        return removed

    def test_webhook(self, url: str) -> bool:
        """Test webhook connectivity."""
        payload = json.dumps({
            "event": "test",
            "message": "Auto Forensics webhook test",
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Auto-Forensics/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 201, 204)
        except Exception as exc:
            logger.error("Webhook test failed: %s", exc)
            return False

    def send_alert(self, alert: Alert) -> dict[str, bool]:
        """Send an alert to all configured channels.

        Returns dict with success status per channel.
        """
        results: dict[str, bool] = {}
        rule = self._find_rule(alert.rule_id)
        if not rule:
            logger.warning("Rule %s not found for alert", alert.rule_id)
            return results

        for channel in rule.channels:
            try:
                if channel == AlertChannel.WEBHOOK and rule.webhook_url:
                    ok = self._send_webhook(rule.webhook_url, alert)
                    results["webhook"] = ok
                    if ok:
                        alert.sent_channels.append("webhook")

                elif channel == AlertChannel.EMAIL and rule.email_recipients:
                    ok = self._send_email(
                        rule.email_recipients, rule.smtp_config, alert
                    )
                    results["email"] = ok
                    if ok:
                        alert.sent_channels.append("email")

                elif channel == AlertChannel.CONSOLE:
                    self._send_console(alert)
                    results["console"] = True
                    alert.sent_channels.append("console")

            except Exception as exc:
                logger.error("Failed to send alert to %s: %s", channel, exc)
                results[channel.value] = False

        self._add_to_history(alert)
        return results

    def _find_rule(self, rule_id: str) -> AlertRule | None:
        with self._lock:
            for r in self.rules:
                if r.rule_id == rule_id:
                    return r
        return None

    def _add_to_history(self, alert: Alert) -> None:
        with self._lock:
            self._alert_history.append(alert)
            if len(self._alert_history) > self._max_history:
                self._alert_history = self._alert_history[-self._max_history:]

    def _send_webhook(self, url: str, alert: Alert) -> bool:
        """Send alert via webhook POST."""
        payload = json.dumps({
            "event": "alert",
            "alert": alert.to_dict(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Auto-Forensics/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status in (200, 201, 202, 204)
        except Exception as exc:
            logger.error("Webhook send failed: %s", exc)
            return False

    def _send_email(
        self, recipients: list[str], smtp_config: SMTPConfig | None, alert: Alert
    ) -> bool:
        """Send alert via SMTP email."""
        if not smtp_config or not recipients:
            return False
        try:
            msg = MIMEText(
                f"Auto Forensics Alert\n\n"
                f"Severity: {alert.severity.value.upper()}\n"
                f"Case: {alert.case_id}\n"
                f"Message: {alert.message}\n"
                f"Time: {alert.timestamp}\n"
                f"\nData: {json.dumps(alert.data, indent=2)}"
            )
            msg["Subject"] = f"[{alert.severity.value.upper()}] Auto Forensics Alert"
            msg["From"] = smtp_config.from_addr
            msg["To"] = ", ".join(recipients)

            with smtplib.SMTP(smtp_config.host, smtp_config.port) as server:
                if smtp_config.use_tls:
                    server.starttls()
                if smtp_config.username and smtp_config.password:
                    server.login(smtp_config.username, smtp_config.password)
                server.send_message(msg)

            return True
        except Exception as exc:
            logger.error("Email send failed: %s", exc)
            return False

    def _send_console(self, alert: Alert) -> None:
        """Log alert to console."""
        level_map = {
            AlertSeverity.CRITICAL: "CRITICAL",
            AlertSeverity.HIGH: "ERROR",
            AlertSeverity.MEDIUM: "WARNING",
            AlertSeverity.LOW: "INFO",
            AlertSeverity.INFO: "INFO",
        }
        level = level_map.get(alert.severity, "INFO")
        msg = f"[ALERT:{level}] Case {alert.case_id}: {alert.message}"
        logger.log(getattr(logging, level), msg)

    def evaluate_case(
        self, case_id: str, case_data: dict[str, Any]
    ) -> list[Alert]:
        """Evaluate a case against all rules and trigger matching alerts."""
        alerts: list[Alert] = []
        findings = case_data.get("findings", [])
        iocs = case_data.get("iocs", [])
        summary = case_data.get("summary", {})
        risk_score = summary.get("risk_score", 0) or summary.get(
            "total_risk_score", 0
        )

        with self._lock:
            rules_to_check = list(self.rules)

        for rule in rules_to_check:
            if not rule.enabled:
                continue

            cond = rule.trigger_condition
            cond_type = cond.get("type")
            triggered = False
            severity = AlertSeverity.MEDIUM

            if cond_type == "severity_threshold":
                threshold = cond.get("threshold", "high")
                sev_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                req_level = sev_map.get(threshold, 3)
                for f in findings:
                    f_sev = str(f.get("severity", "")).lower()
                    if sev_map.get(f_sev, 0) >= req_level:
                        triggered = True
                        severity = AlertSeverity(f_sev) if f_sev else severity
                        break

            elif cond_type == "finding_count":
                count = int(cond.get("count", 1))
                if len(findings) >= count:
                    triggered = True

            elif cond_type == "risk_score":
                threshold = int(cond.get("threshold", 50))
                if risk_score >= threshold:
                    triggered = True
                    severity = AlertSeverity.HIGH if risk_score > 70 else AlertSeverity.MEDIUM

            elif cond_type == "critical_ioc":
                for ioc in iocs:
                    ioc_type = str(ioc.get("ioc_type") or ioc.get("type", ""))
                    if ioc_type.lower() in ["malware", "c2", "apt"]:
                        triggered = True
                        severity = AlertSeverity.CRITICAL
                        break

            if triggered:
                alert = Alert(
                    alert_id=f"alert-{int(time.time()*1000)}",
                    rule_id=rule.rule_id,
                    case_id=case_id,
                    severity=severity,
                    message=f"Rule '{rule.name}' triggered: {rule.description}",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    data={"findings_count": len(findings), "iocs_count": len(iocs)},
                )
                self.send_alert(alert)
                alerts.append(alert)

        return alerts

    def notify_analysis_complete(
        self, case_id: str, result: dict[str, Any]
    ) -> list[Alert]:
        """Send completion notification for analysis job."""
        default_rule = AlertRule(
            rule_id="auto-analysis-complete",
            name="Analysis Complete",
            description="Analysis job finished",
            enabled=True,
            trigger_condition={"type": "always"},
            channels=[AlertChannel.CONSOLE],
        )
        alert = Alert(
            alert_id=f"complete-{int(time.time()*1000)}",
            rule_id=default_rule.rule_id,
            case_id=case_id,
            severity=AlertSeverity.INFO,
            message=f"Analysis complete for case {case_id}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=result,
        )
        self.send_alert(alert)
        return [alert]
