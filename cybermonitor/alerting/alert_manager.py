# cybermonitor/alerting/alert_manager.py
"""
Alert Manager - Unified alerting across multiple channels.
"""

import logging
from typing import List, Optional
from dataclasses import dataclass, field

from cybermonitor.alerting.sns_alert import SNSAlert
from cybermonitor.alerting.slack_alert import SlackAlert

logger = logging.getLogger(__name__)


@dataclass
class AlertManager:
    """
    Unified alert manager that sends to multiple channels.

    Supports:
    - AWS SNS
    - Slack webhooks
    - Console logging (always enabled)
    """

    sns_topic_arn: Optional[str] = None
    slack_webhook_url: Optional[str] = None
    enable_sns: bool = True
    enable_slack: bool = True
    enable_console: bool = True

    _sns_alert: Optional[SNSAlert] = field(default=None, repr=False)
    _slack_alert: Optional[SlackAlert] = field(default=None, repr=False)

    def __post_init__(self):
        """Initialize alert backends."""
        if self.enable_sns and self.sns_topic_arn:
            self._sns_alert = SNSAlert(topic_arn=self.sns_topic_arn)
            logger.info(f"SNS alerting enabled: {self.sns_topic_arn}")

        if self.enable_slack and self.slack_webhook_url:
            self._slack_alert = SlackAlert(webhook_url=self.slack_webhook_url)
            logger.info("Slack alerting enabled")

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "info",
        metadata: Optional[dict] = None
    ) -> dict:
        """
        Send an alert to all enabled channels.

        Args:
            title: Alert title
            message: Alert message body
            severity: Severity level (critical, high, medium, low, info)
            metadata: Additional metadata to include

        Returns:
            Dictionary with success status for each channel
        """
        results = {"console": False, "sns": False, "slack": False}

        # Console logging (always)
        if self.enable_console:
            self._log_alert(title, message, severity, metadata)
            results["console"] = True

        # SNS
        if self._sns_alert:
            try:
                results["sns"] = self._sns_alert.send_alert(title, message, severity, metadata)
            except Exception as e:
                logger.error(f"SNS alert failed: {e}")

        # Slack
        if self._slack_alert:
            try:
                results["slack"] = self._slack_alert.send_alert(title, message, severity, metadata)
            except Exception as e:
                logger.error(f"Slack alert failed: {e}")

        return results

    def send_finding_alert(self, finding) -> dict:
        """
        Send an alert for a security finding to all channels.

        Args:
            finding: Finding object from scanner

        Returns:
            Dictionary with success status for each channel
        """
        return self.send_alert(
            title=finding.title,
            message=finding.description,
            severity=finding.severity.value,
            metadata={
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "remediation": finding.remediation,
                **finding.metadata
            }
        )

    def send_batch_alert(self, findings: List, scan_type: str = "Security Scan") -> dict:
        """
        Send a summary alert for multiple findings.

        Args:
            findings: List of Finding objects
            scan_type: Type of scan that produced findings

        Returns:
            Dictionary with success status for each channel
        """
        results = {"console": False, "sns": False, "slack": False}

        if not findings:
            logger.info(f"{scan_type} complete - no findings")
            return results

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

        message_lines = [
            f"Security scan completed with {len(findings)} findings:",
            f"  Critical: {severity_counts['critical']}",
            f"  High: {severity_counts['high']}",
            f"  Medium: {severity_counts['medium']}",
            f"  Low: {severity_counts['low']}"
        ]
        message = "\n".join(message_lines)

        # Console
        if self.enable_console:
            self._log_alert(title, message, overall_severity, {"findings_count": len(findings)})
            results["console"] = True

            # Log individual critical/high findings
            for f in findings:
                if f.severity.value in ("critical", "high"):
                    logger.warning(f"  [{f.severity.value.upper()}] {f.title}: {f.resource_id}")

        # SNS batch
        if self._sns_alert:
            try:
                results["sns"] = self._sns_alert.send_batch_alert(findings, scan_type)
            except Exception as e:
                logger.error(f"SNS batch alert failed: {e}")

        # Slack batch
        if self._slack_alert:
            try:
                results["slack"] = self._slack_alert.send_batch_alert(findings, scan_type)
            except Exception as e:
                logger.error(f"Slack batch alert failed: {e}")

        return results

    def send_critical_findings(self, findings: List) -> int:
        """
        Send individual alerts for critical findings only.

        Args:
            findings: List of Finding objects

        Returns:
            Number of alerts sent
        """
        count = 0
        for finding in findings:
            if finding.severity.value == "critical":
                self.send_finding_alert(finding)
                count += 1
        return count

    def _log_alert(
        self,
        title: str,
        message: str,
        severity: str,
        metadata: Optional[dict]
    ):
        """Log alert to console."""
        severity_upper = severity.upper()

        if severity in ("critical", "high"):
            log_func = logger.warning
        elif severity == "medium":
            log_func = logger.info
        else:
            log_func = logger.debug

        log_func(f"[{severity_upper}] {title}")
        log_func(f"  {message}")

        if metadata:
            for key, value in metadata.items():
                log_func(f"  {key}: {value}")
