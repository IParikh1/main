# cybermonitor/alerting/slack_alert.py
"""
Slack Alert integration for security notifications.
"""

import logging
import json
from typing import List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SlackAlert:
    """
    Slack Alert sender using incoming webhooks.

    Sends formatted security alerts to a Slack channel.
    """

    webhook_url: str
    channel: Optional[str] = None
    username: str = "CyberMonitor"
    icon_emoji: str = ":shield:"

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "info",
        metadata: Optional[dict] = None
    ) -> bool:
        """
        Send an alert to Slack.

        Args:
            title: Alert title
            message: Alert message body
            severity: Severity level (critical, high, medium, low, info)
            metadata: Additional metadata to include

        Returns:
            True if alert was sent successfully
        """
        try:
            import requests
        except ImportError:
            raise ImportError("requests is required for Slack alerts. Install with: pip install requests")

        try:
            payload = self._build_payload(title, message, severity, metadata)

            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code == 200:
                logger.info(f"Alert sent to Slack: {title}")
                return True
            else:
                logger.error(f"Slack API error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

    def send_finding_alert(self, finding) -> bool:
        """
        Send an alert for a security finding.

        Args:
            finding: Finding object from scanner

        Returns:
            True if alert was sent successfully
        """
        return self.send_alert(
            title=finding.title,
            message=finding.description,
            severity=finding.severity.value,
            metadata={
                "Resource Type": finding.resource_type,
                "Resource ID": finding.resource_id,
                "Remediation": finding.remediation
            }
        )

    def send_batch_alert(self, findings: List, scan_type: str = "Security Scan") -> bool:
        """
        Send a summary alert for multiple findings.

        Args:
            findings: List of Finding objects
            scan_type: Type of scan that produced findings

        Returns:
            True if alert was sent successfully
        """
        if not findings:
            return True

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            severity_counts[f.severity.value] += 1

        # Determine overall severity
        if severity_counts["critical"] > 0:
            overall_severity = "critical"
        elif severity_counts["high"] > 0:
            overall_severity = "high"
        elif severity_counts["medium"] > 0:
            overall_severity = "medium"
        else:
            overall_severity = "low"

        title = f"{scan_type} Complete - {len(findings)} Issues Found"

        summary_lines = [
            f"*Critical:* {severity_counts['critical']}",
            f"*High:* {severity_counts['high']}",
            f"*Medium:* {severity_counts['medium']}",
            f"*Low:* {severity_counts['low']}"
        ]

        message = "\n".join(summary_lines)

        # Build detailed findings for attachment
        metadata = {
            "Total Findings": len(findings),
            "Scan Type": scan_type
        }

        return self.send_alert(
            title=title,
            message=message,
            severity=overall_severity,
            metadata=metadata
        )

    def _build_payload(
        self,
        title: str,
        message: str,
        severity: str,
        metadata: Optional[dict]
    ) -> dict:
        """Build the Slack webhook payload."""
        color_map = {
            "critical": "#FF0000",  # Red
            "high": "#FF6600",      # Orange
            "medium": "#FFCC00",    # Yellow
            "low": "#00CC00",       # Green
            "info": "#0066CC"       # Blue
        }

        color = color_map.get(severity.lower(), "#808080")

        # Build attachment fields from metadata
        fields = []
        if metadata:
            for key, value in metadata.items():
                fields.append({
                    "title": key,
                    "value": str(value),
                    "short": len(str(value)) < 40
                })

        attachment = {
            "fallback": f"[{severity.upper()}] {title}",
            "color": color,
            "title": f":warning: {title}",
            "text": message,
            "fields": fields,
            "footer": "CyberMonitor Security Alert",
            "ts": int(__import__('time').time())
        }

        payload = {
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [attachment]
        }

        if self.channel:
            payload["channel"] = self.channel

        return payload
