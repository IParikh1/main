# cybermonitor/detectors/cloudtrail_detector.py
"""
CloudTrail-based threat detection for real-time security monitoring.

Analyzes CloudTrail events to detect:
- Suspicious API calls
- Activity from suspicious regions
- Behavioral anomalies
- Unauthorized actions
"""

import logging
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime

from cybermonitor.scanners.aws_scanner import Finding, Severity
from cybermonitor.config import config

logger = logging.getLogger(__name__)


@dataclass
class ThreatEvent:
    """Represents a detected threat from CloudTrail."""
    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    user_identity: str
    source_ip: str
    aws_region: str
    severity: Severity
    threat_type: str
    description: str
    raw_event: Dict[str, Any] = field(default_factory=dict)


class CloudTrailDetector:
    """
    Real-time threat detector for AWS CloudTrail events.

    Can be used:
    - As a Lambda handler for real-time detection
    - For batch analysis of CloudTrail logs
    """

    def __init__(
        self,
        suspicious_regions: Optional[List[str]] = None,
        monitored_actions: Optional[List[str]] = None
    ):
        """
        Initialize the CloudTrail detector.

        Args:
            suspicious_regions: List of regions to flag as suspicious
            monitored_actions: List of API actions to monitor
        """
        self.suspicious_regions = suspicious_regions or config.detection.suspicious_regions
        self.monitored_actions = set(monitored_actions or config.detection.monitored_actions)
        self.detected_threats: List[ThreatEvent] = []

        # User behavior tracking (in production, use DynamoDB)
        self._user_history: Dict[str, Dict] = {}

    def analyze_event(self, event: Dict[str, Any]) -> Optional[ThreatEvent]:
        """
        Analyze a single CloudTrail event for threats.

        Args:
            event: CloudTrail event dictionary

        Returns:
            ThreatEvent if threat detected, None otherwise
        """
        event_name = event.get('eventName', '')
        event_source = event.get('eventSource', '')
        event_time = event.get('eventTime', '')
        aws_region = event.get('awsRegion', '')
        source_ip = event.get('sourceIPAddress', '')

        user_identity = event.get('userIdentity', {})
        user_arn = user_identity.get('arn', 'Unknown')

        event_id = event.get('eventID', f"{event_time}-{event_name}")

        # Check for suspicious region
        if self._is_suspicious_region(aws_region):
            threat = ThreatEvent(
                event_id=event_id,
                event_time=self._parse_time(event_time),
                event_name=event_name,
                event_source=event_source,
                user_identity=user_arn,
                source_ip=source_ip,
                aws_region=aws_region,
                severity=Severity.HIGH,
                threat_type="SUSPICIOUS_REGION",
                description=f"API call from suspicious region: {aws_region}",
                raw_event=event
            )
            self.detected_threats.append(threat)
            logger.warning(f"Threat detected: {threat.threat_type} - {event_name} from {aws_region}")
            return threat

        # Check for monitored sensitive actions
        if event_name in self.monitored_actions:
            severity = self._get_action_severity(event_name)
            threat = ThreatEvent(
                event_id=event_id,
                event_time=self._parse_time(event_time),
                event_name=event_name,
                event_source=event_source,
                user_identity=user_arn,
                source_ip=source_ip,
                aws_region=aws_region,
                severity=severity,
                threat_type="SENSITIVE_ACTION",
                description=f"Sensitive action detected: {event_name}",
                raw_event=event
            )
            self.detected_threats.append(threat)
            logger.warning(f"Threat detected: {threat.threat_type} - {event_name} by {user_arn}")
            return threat

        # Check for behavioral anomaly
        if self._is_anomalous_behavior(user_arn, event_name, source_ip):
            threat = ThreatEvent(
                event_id=event_id,
                event_time=self._parse_time(event_time),
                event_name=event_name,
                event_source=event_source,
                user_identity=user_arn,
                source_ip=source_ip,
                aws_region=aws_region,
                severity=Severity.MEDIUM,
                threat_type="BEHAVIORAL_ANOMALY",
                description=f"Unusual behavior detected for user {user_arn}",
                raw_event=event
            )
            self.detected_threats.append(threat)
            logger.info(f"Anomaly detected: {event_name} by {user_arn} from {source_ip}")
            return threat

        # Update user history
        self._update_user_history(user_arn, event_name, source_ip)
        return None

    def analyze_events(self, events: List[Dict[str, Any]]) -> List[ThreatEvent]:
        """
        Analyze multiple CloudTrail events.

        Args:
            events: List of CloudTrail event dictionaries

        Returns:
            List of detected threats
        """
        threats = []
        for event in events:
            threat = self.analyze_event(event)
            if threat:
                threats.append(threat)
        return threats

    def lambda_handler(self, event: Dict, context: Any) -> Dict:
        """
        AWS Lambda handler for processing CloudTrail events.

        Can be triggered by:
        - S3 event notification when CloudTrail logs are delivered
        - CloudWatch Events rule
        - Direct invocation

        Args:
            event: Lambda event (contains CloudTrail records)
            context: Lambda context

        Returns:
            Response dictionary
        """
        logger.info("Processing CloudTrail events via Lambda")

        records = event.get('Records', [])
        threats = []

        for record in records:
            # Handle S3 event (CloudTrail log delivery)
            if 'eventSource' in record and record.get('eventSource') == 'cloudtrail.amazonaws.com':
                threat = self.analyze_event(record)
                if threat:
                    threats.append(threat)
            # Handle direct CloudTrail event format
            elif 'eventName' in record:
                threat = self.analyze_event(record)
                if threat:
                    threats.append(threat)

        response = {
            "statusCode": 200,
            "body": {
                "processed": len(records),
                "threats_detected": len(threats),
                "threats": [
                    {
                        "event_id": t.event_id,
                        "threat_type": t.threat_type,
                        "severity": t.severity.value,
                        "event_name": t.event_name,
                        "user": t.user_identity
                    }
                    for t in threats
                ]
            }
        }

        if threats:
            logger.warning(f"Detected {len(threats)} threats in {len(records)} events")

        return response

    def _is_suspicious_region(self, region: str) -> bool:
        """Check if region is in the suspicious regions list."""
        # Note: AWS regions are like 'us-east-1', but geolocation might give country names
        # This is a simplified check - in production, you'd use IP geolocation
        for suspicious in self.suspicious_regions:
            if suspicious.lower() in region.lower():
                return True
        return False

    def _get_action_severity(self, action: str) -> Severity:
        """Determine severity based on action type."""
        critical_actions = {
            'DeleteBucket', 'DeleteUser', 'DeletePolicy',
            'DeleteSecurityGroup', 'TerminateInstances'
        }
        high_actions = {
            'PutBucketAcl', 'PutBucketPolicy', 'CreateUser',
            'AttachUserPolicy', 'AuthorizeSecurityGroupIngress'
        }

        if action in critical_actions:
            return Severity.CRITICAL
        elif action in high_actions:
            return Severity.HIGH
        else:
            return Severity.MEDIUM

    def _is_anomalous_behavior(self, user_arn: str, action: str, source_ip: str) -> bool:
        """
        Check if the current action is anomalous based on user history.

        Simple implementation - in production, use ML models or DynamoDB.
        """
        if user_arn not in self._user_history:
            return False  # First time user - not anomalous yet

        history = self._user_history[user_arn]
        known_actions = history.get('actions', set())
        known_ips = history.get('ips', set())

        # Flag if action AND IP are both new for this user
        is_new_action = action not in known_actions
        is_new_ip = source_ip not in known_ips

        return is_new_action and is_new_ip

    def _update_user_history(self, user_arn: str, action: str, source_ip: str):
        """Update user behavior history."""
        if user_arn not in self._user_history:
            self._user_history[user_arn] = {
                'actions': set(),
                'ips': set(),
                'last_seen': None
            }

        history = self._user_history[user_arn]
        history['actions'].add(action)
        history['ips'].add(source_ip)
        history['last_seen'] = datetime.utcnow()

        # Limit history size (in production, use TTL in DynamoDB)
        if len(history['actions']) > 100:
            history['actions'] = set(list(history['actions'])[-50:])
        if len(history['ips']) > 50:
            history['ips'] = set(list(history['ips'])[-25:])

    def _parse_time(self, time_str: str) -> datetime:
        """Parse CloudTrail timestamp."""
        try:
            return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.utcnow()

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats."""
        summary = {
            "total_threats": len(self.detected_threats),
            "by_severity": {
                Severity.CRITICAL.value: 0,
                Severity.HIGH.value: 0,
                Severity.MEDIUM.value: 0,
                Severity.LOW.value: 0
            },
            "by_type": {}
        }

        for threat in self.detected_threats:
            summary["by_severity"][threat.severity.value] += 1

            if threat.threat_type not in summary["by_type"]:
                summary["by_type"][threat.threat_type] = 0
            summary["by_type"][threat.threat_type] += 1

        return summary

    def to_findings(self) -> List[Finding]:
        """Convert detected threats to Finding objects for unified reporting."""
        findings = []
        for threat in self.detected_threats:
            finding = Finding(
                resource_type="AWS::CloudTrail::Event",
                resource_id=threat.event_id,
                title=f"CloudTrail: {threat.threat_type}",
                description=threat.description,
                severity=threat.severity,
                remediation=self._get_remediation(threat.threat_type),
                metadata={
                    "event_name": threat.event_name,
                    "user": threat.user_identity,
                    "source_ip": threat.source_ip,
                    "region": threat.aws_region,
                    "event_time": str(threat.event_time)
                }
            )
            findings.append(finding)
        return findings

    def _get_remediation(self, threat_type: str) -> str:
        """Get remediation guidance for threat type."""
        remediations = {
            "SUSPICIOUS_REGION": "Investigate the source of this activity. Consider blocking access from suspicious regions using IAM policies or AWS WAF.",
            "SENSITIVE_ACTION": "Review the action and ensure it was authorized. Consider implementing additional approval workflows for sensitive operations.",
            "BEHAVIORAL_ANOMALY": "Investigate if this user's credentials have been compromised. Review recent activity and consider rotating credentials."
        }
        return remediations.get(threat_type, "Review and investigate this security event.")
