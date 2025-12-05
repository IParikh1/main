# tests/test_detectors.py
"""Tests for CyberMonitor threat detectors."""

import pytest
from unittest.mock import MagicMock
from datetime import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybermonitor.detectors.cloudtrail_detector import CloudTrailDetector, ThreatEvent
from cybermonitor.scanners.aws_scanner import Severity


class TestCloudTrailDetector:
    """Tests for CloudTrail threat detector."""

    def test_detector_initialization(self):
        """Test detector initializes correctly."""
        detector = CloudTrailDetector()

        assert detector.detected_threats == []
        assert "North Korea" in detector.suspicious_regions
        assert "DeleteBucket" in detector.monitored_actions

    def test_detector_custom_config(self):
        """Test detector accepts custom configuration."""
        detector = CloudTrailDetector(
            suspicious_regions=["TestRegion"],
            monitored_actions=["TestAction"]
        )

        assert detector.suspicious_regions == ["TestRegion"]
        assert "TestAction" in detector.monitored_actions

    def test_detect_suspicious_region(self):
        """Test detection of activity from suspicious region."""
        detector = CloudTrailDetector(suspicious_regions=["russia"])

        event = {
            "eventID": "test-123",
            "eventTime": "2024-01-15T10:00:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "russia-west-1",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"arn": "arn:aws:iam::123:user/test"}
        }

        threat = detector.analyze_event(event)

        assert threat is not None
        assert threat.threat_type == "SUSPICIOUS_REGION"
        assert threat.severity == Severity.HIGH

    def test_detect_monitored_action(self):
        """Test detection of sensitive actions."""
        detector = CloudTrailDetector()

        event = {
            "eventID": "test-456",
            "eventTime": "2024-01-15T10:00:00Z",
            "eventName": "DeleteBucket",
            "eventSource": "s3.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"arn": "arn:aws:iam::123:user/test"}
        }

        threat = detector.analyze_event(event)

        assert threat is not None
        assert threat.threat_type == "SENSITIVE_ACTION"
        assert threat.severity == Severity.CRITICAL

    def test_no_threat_for_normal_event(self):
        """Test that normal events don't trigger threats."""
        detector = CloudTrailDetector()

        # First, establish some history for the user
        detector._user_history["arn:aws:iam::123:user/test"] = {
            "actions": {"DescribeInstances"},
            "ips": {"1.2.3.4"},
            "last_seen": datetime.utcnow()
        }

        event = {
            "eventID": "test-789",
            "eventTime": "2024-01-15T10:00:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "1.2.3.4",
            "userIdentity": {"arn": "arn:aws:iam::123:user/test"}
        }

        threat = detector.analyze_event(event)

        assert threat is None

    def test_analyze_multiple_events(self):
        """Test analyzing multiple events."""
        detector = CloudTrailDetector()

        events = [
            {
                "eventID": "test-1",
                "eventTime": "2024-01-15T10:00:00Z",
                "eventName": "DeleteBucket",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userIdentity": {"arn": "arn:aws:iam::123:user/test"}
            },
            {
                "eventID": "test-2",
                "eventTime": "2024-01-15T10:01:00Z",
                "eventName": "DescribeInstances",
                "eventSource": "ec2.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userIdentity": {"arn": "arn:aws:iam::123:user/test"}
            }
        ]

        threats = detector.analyze_events(events)

        assert len(threats) >= 1
        assert any(t.event_name == "DeleteBucket" for t in threats)

    def test_lambda_handler_format(self):
        """Test Lambda handler returns correct format."""
        detector = CloudTrailDetector()

        event = {
            "Records": [{
                "eventID": "test-123",
                "eventTime": "2024-01-15T10:00:00Z",
                "eventName": "DeleteBucket",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "1.2.3.4",
                "userIdentity": {"arn": "arn:aws:iam::123:user/test"}
            }]
        }

        response = detector.lambda_handler(event, None)

        assert response["statusCode"] == 200
        assert "body" in response
        assert "processed" in response["body"]
        assert "threats_detected" in response["body"]

    def test_get_summary(self):
        """Test summary generation."""
        detector = CloudTrailDetector()

        # Add some threats
        detector.detected_threats = [
            ThreatEvent(
                event_id="1",
                event_time=datetime.utcnow(),
                event_name="DeleteBucket",
                event_source="s3.amazonaws.com",
                user_identity="test-user",
                source_ip="1.2.3.4",
                aws_region="us-east-1",
                severity=Severity.CRITICAL,
                threat_type="SENSITIVE_ACTION",
                description="Test"
            ),
            ThreatEvent(
                event_id="2",
                event_time=datetime.utcnow(),
                event_name="ListBuckets",
                event_source="s3.amazonaws.com",
                user_identity="test-user",
                source_ip="1.2.3.4",
                aws_region="russia",
                severity=Severity.HIGH,
                threat_type="SUSPICIOUS_REGION",
                description="Test"
            )
        ]

        summary = detector.get_summary()

        assert summary["total_threats"] == 2
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
        assert "SENSITIVE_ACTION" in summary["by_type"]
        assert "SUSPICIOUS_REGION" in summary["by_type"]

    def test_to_findings_conversion(self):
        """Test conversion of threats to findings."""
        detector = CloudTrailDetector()

        detector.detected_threats = [
            ThreatEvent(
                event_id="test-123",
                event_time=datetime.utcnow(),
                event_name="DeleteBucket",
                event_source="s3.amazonaws.com",
                user_identity="test-user",
                source_ip="1.2.3.4",
                aws_region="us-east-1",
                severity=Severity.CRITICAL,
                threat_type="SENSITIVE_ACTION",
                description="Test threat"
            )
        ]

        findings = detector.to_findings()

        assert len(findings) == 1
        assert findings[0].resource_type == "AWS::CloudTrail::Event"
        assert findings[0].severity == Severity.CRITICAL


class TestThreatEvent:
    """Tests for ThreatEvent dataclass."""

    def test_threat_event_creation(self):
        """Test ThreatEvent creation."""
        threat = ThreatEvent(
            event_id="test-123",
            event_time=datetime.utcnow(),
            event_name="TestEvent",
            event_source="test.amazonaws.com",
            user_identity="test-user",
            source_ip="1.2.3.4",
            aws_region="us-east-1",
            severity=Severity.HIGH,
            threat_type="TEST_TYPE",
            description="Test description"
        )

        assert threat.event_id == "test-123"
        assert threat.event_name == "TestEvent"
        assert threat.severity == Severity.HIGH


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
