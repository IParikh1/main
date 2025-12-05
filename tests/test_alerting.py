# tests/test_alerting.py
"""Tests for CyberMonitor alerting system."""

import pytest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybermonitor.alerting.alert_manager import AlertManager
from cybermonitor.alerting.slack_alert import SlackAlert
from cybermonitor.alerting.sns_alert import SNSAlert
from cybermonitor.scanners.aws_scanner import Finding, Severity


class TestSlackAlert:
    """Tests for Slack alerting."""

    def test_slack_alert_initialization(self):
        """Test Slack alert initializes correctly."""
        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")

        assert alert.webhook_url == "https://hooks.slack.com/test"
        assert alert.username == "CyberMonitor"

    def test_build_payload(self):
        """Test payload building."""
        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")

        payload = alert._build_payload(
            title="Test Alert",
            message="Test message",
            severity="critical",
            metadata={"key": "value"}
        )

        assert "attachments" in payload
        assert payload["attachments"][0]["color"] == "#FF0000"  # Red for critical
        assert "Test Alert" in payload["attachments"][0]["title"]

    def test_build_payload_different_severities(self):
        """Test payload colors for different severities."""
        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")

        severities = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "medium": "#FFCC00",
            "low": "#00CC00",
            "info": "#0066CC"
        }

        for severity, expected_color in severities.items():
            payload = alert._build_payload("Test", "msg", severity, None)
            assert payload["attachments"][0]["color"] == expected_color

    @patch('requests.post')
    def test_send_alert_success(self, mock_post):
        """Test successful alert sending."""
        mock_post.return_value.status_code = 200

        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")
        result = alert.send_alert("Test", "Message", "high")

        assert result is True
        mock_post.assert_called_once()

    @patch('requests.post')
    def test_send_alert_failure(self, mock_post):
        """Test failed alert sending."""
        mock_post.return_value.status_code = 400
        mock_post.return_value.text = "Bad request"

        alert = SlackAlert(webhook_url="https://hooks.slack.com/test")
        result = alert.send_alert("Test", "Message", "high")

        assert result is False


class TestSNSAlert:
    """Tests for SNS alerting."""

    def test_sns_alert_initialization(self):
        """Test SNS alert initializes correctly."""
        alert = SNSAlert(topic_arn="arn:aws:sns:us-east-1:123:test")

        assert alert.topic_arn == "arn:aws:sns:us-east-1:123:test"
        assert alert.subject_prefix == "[CyberMonitor]"

    def test_format_message(self):
        """Test message formatting."""
        alert = SNSAlert(topic_arn="arn:aws:sns:us-east-1:123:test")

        message = alert._format_message(
            title="Test Alert",
            message="Test description",
            severity="critical",
            metadata={"resource": "test-bucket"}
        )

        assert "CYBERMONITOR SECURITY ALERT" in message
        assert "Test Alert" in message
        assert "CRITICAL" in message
        assert "resource: test-bucket" in message


class TestAlertManager:
    """Tests for unified alert manager."""

    def test_alert_manager_initialization(self):
        """Test alert manager initializes correctly."""
        manager = AlertManager(
            sns_topic_arn=None,
            slack_webhook_url=None,
            enable_console=True
        )

        assert manager.enable_console is True
        assert manager._sns_alert is None
        assert manager._slack_alert is None

    def test_alert_manager_with_slack(self):
        """Test alert manager with Slack enabled."""
        manager = AlertManager(
            slack_webhook_url="https://hooks.slack.com/test",
            enable_slack=True
        )

        assert manager._slack_alert is not None

    def test_send_alert_console_only(self):
        """Test sending alert to console only."""
        manager = AlertManager(
            enable_console=True,
            enable_sns=False,
            enable_slack=False
        )

        results = manager.send_alert("Test", "Message", "high")

        assert results["console"] is True
        assert results["sns"] is False
        assert results["slack"] is False

    def test_send_batch_alert_empty(self):
        """Test batch alert with no findings."""
        manager = AlertManager(enable_console=True)

        results = manager.send_batch_alert([], "Test Scan")

        # Should return without error
        assert isinstance(results, dict)

    def test_send_batch_alert_with_findings(self):
        """Test batch alert with findings."""
        manager = AlertManager(enable_console=True)

        findings = [
            Finding("type1", "id1", "Critical Issue", "desc", Severity.CRITICAL, "fix"),
            Finding("type2", "id2", "High Issue", "desc", Severity.HIGH, "fix"),
            Finding("type3", "id3", "Medium Issue", "desc", Severity.MEDIUM, "fix"),
        ]

        results = manager.send_batch_alert(findings, "Test Scan")

        assert results["console"] is True

    def test_send_finding_alert(self):
        """Test sending alert for single finding."""
        manager = AlertManager(enable_console=True)

        finding = Finding(
            resource_type="AWS::S3::Bucket",
            resource_id="test-bucket",
            title="Public Bucket",
            description="Bucket is publicly accessible",
            severity=Severity.CRITICAL,
            remediation="Block public access"
        )

        results = manager.send_finding_alert(finding)

        assert results["console"] is True

    def test_send_critical_findings(self):
        """Test sending alerts for critical findings only."""
        manager = AlertManager(enable_console=True)

        findings = [
            Finding("type1", "id1", "Critical", "desc", Severity.CRITICAL, "fix"),
            Finding("type2", "id2", "High", "desc", Severity.HIGH, "fix"),
            Finding("type3", "id3", "Low", "desc", Severity.LOW, "fix"),
        ]

        count = manager.send_critical_findings(findings)

        # Should only send for critical findings
        assert count == 1


class TestAlertingIntegration:
    """Integration tests for alerting."""

    def test_finding_to_alert_flow(self):
        """Test complete flow from finding to alert."""
        manager = AlertManager(enable_console=True)

        finding = Finding(
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-12345",
            title="Security Group Exposes SSH",
            description="Security group allows SSH from 0.0.0.0/0",
            severity=Severity.CRITICAL,
            remediation="Restrict SSH access",
            metadata={"port": 22, "cidr": "0.0.0.0/0"}
        )

        results = manager.send_finding_alert(finding)

        assert results["console"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
