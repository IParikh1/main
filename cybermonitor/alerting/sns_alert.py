# cybermonitor/alerting/sns_alert.py
"""
AWS SNS Alert integration for security notifications.
"""

import logging
from typing import List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SNSAlert:
    """
    AWS SNS Alert sender for security notifications.

    Sends alerts to an SNS topic which can be configured to:
    - Send emails
    - Trigger Lambda functions
    - Push to SQS queues
    - Send SMS messages
    """

    topic_arn: str
    subject_prefix: str = "[CyberMonitor]"
    _sns_client = None
    _boto3 = None

    @property
    def boto3(self):
        """Lazy load boto3."""
        if self._boto3 is None:
            try:
                import boto3
                self._boto3 = boto3
            except ImportError:
                raise ImportError("boto3 is required for SNS alerts. Install with: pip install boto3")
        return self._boto3

    @property
    def sns_client(self):
        """Lazy load SNS client."""
        if self._sns_client is None:
            self._sns_client = self.boto3.client('sns')
        return self._sns_client

    def send_alert(
        self,
        title: str,
        message: str,
        severity: str = "info",
        metadata: Optional[dict] = None
    ) -> bool:
        """
        Send an alert to the SNS topic.

        Args:
            title: Alert title
            message: Alert message body
            severity: Severity level (critical, high, medium, low, info)
            metadata: Additional metadata to include

        Returns:
            True if alert was sent successfully
        """
        try:
            subject = f"{self.subject_prefix} [{severity.upper()}] {title}"
            # SNS subjects are limited to 100 characters
            subject = subject[:100]

            full_message = self._format_message(title, message, severity, metadata)

            response = self.sns_client.publish(
                TopicArn=self.topic_arn,
                Message=full_message,
                Subject=subject
            )

            message_id = response.get('MessageId')
            logger.info(f"Alert sent to SNS: {message_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send SNS alert: {e}")
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
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "remediation": finding.remediation,
                **finding.metadata
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

        message_lines = [
            f"Security scan completed with {len(findings)} findings:",
            "",
            f"  Critical: {severity_counts['critical']}",
            f"  High: {severity_counts['high']}",
            f"  Medium: {severity_counts['medium']}",
            f"  Low: {severity_counts['low']}",
            "",
            "Top findings:"
        ]

        # Add top 5 critical/high findings
        important_findings = [f for f in findings if f.severity.value in ("critical", "high")][:5]
        for f in important_findings:
            message_lines.append(f"  - [{f.severity.value.upper()}] {f.title}")
            message_lines.append(f"    Resource: {f.resource_id}")

        return self.send_alert(
            title=title,
            message="\n".join(message_lines),
            severity=overall_severity,
            metadata={"total_findings": len(findings), "severity_counts": severity_counts}
        )

    def _format_message(
        self,
        title: str,
        message: str,
        severity: str,
        metadata: Optional[dict]
    ) -> str:
        """Format the alert message."""
        lines = [
            "=" * 60,
            f"CYBERMONITOR SECURITY ALERT",
            "=" * 60,
            "",
            f"Severity: {severity.upper()}",
            f"Title: {title}",
            "",
            "Details:",
            message,
            ""
        ]

        if metadata:
            lines.extend(["", "Metadata:"])
            for key, value in metadata.items():
                lines.append(f"  {key}: {value}")

        lines.extend([
            "",
            "-" * 60,
            "This alert was generated by CyberMonitor",
            "-" * 60
        ])

        return "\n".join(lines)
