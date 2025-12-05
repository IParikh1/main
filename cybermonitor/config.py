# cybermonitor/config.py
"""
Configuration management for CyberMonitor.
All settings are loaded from environment variables with sensible defaults.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AWSConfig:
    """AWS-specific configuration."""
    region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    sns_topic_arn: Optional[str] = field(default_factory=lambda: os.getenv("AWS_SNS_TOPIC_ARN"))
    cloudtrail_bucket: Optional[str] = field(default_factory=lambda: os.getenv("AWS_CLOUDTRAIL_BUCKET"))


@dataclass
class AzureConfig:
    """Azure-specific configuration."""
    subscription_id: Optional[str] = field(default_factory=lambda: os.getenv("AZURE_SUBSCRIPTION_ID"))
    tenant_id: Optional[str] = field(default_factory=lambda: os.getenv("AZURE_TENANT_ID"))
    client_id: Optional[str] = field(default_factory=lambda: os.getenv("AZURE_CLIENT_ID"))


@dataclass
class AlertConfig:
    """Alerting configuration."""
    slack_webhook_url: Optional[str] = field(default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL"))
    enable_sns: bool = field(default_factory=lambda: os.getenv("ENABLE_SNS_ALERTS", "true").lower() == "true")
    enable_slack: bool = field(default_factory=lambda: os.getenv("ENABLE_SLACK_ALERTS", "false").lower() == "true")


@dataclass
class DetectionConfig:
    """Threat detection configuration."""
    suspicious_regions: List[str] = field(default_factory=lambda: [
        "North Korea", "Iran", "Russia", "China", "Syria"
    ])
    monitored_actions: List[str] = field(default_factory=lambda: [
        "DeleteBucket", "PutBucketAcl", "PutBucketPolicy",
        "CreateUser", "DeleteUser", "AttachUserPolicy",
        "UpdatePolicy", "DeletePolicy",
        "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress",
        "CreateSecurityGroup", "DeleteSecurityGroup",
        "StopInstances", "TerminateInstances"
    ])
    anomaly_threshold: float = field(default_factory=lambda: float(os.getenv("ANOMALY_THRESHOLD", "0.1")))
    model_path: Optional[str] = field(default_factory=lambda: os.getenv("ML_MODEL_PATH"))


@dataclass
class Config:
    """Main configuration class for CyberMonitor."""
    aws: AWSConfig = field(default_factory=AWSConfig)
    azure: AzureConfig = field(default_factory=AzureConfig)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)

    # Logging
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Scanning options
    scan_s3: bool = field(default_factory=lambda: os.getenv("SCAN_S3", "true").lower() == "true")
    scan_iam: bool = field(default_factory=lambda: os.getenv("SCAN_IAM", "true").lower() == "true")
    scan_ec2: bool = field(default_factory=lambda: os.getenv("SCAN_EC2", "true").lower() == "true")
    scan_azure_storage: bool = field(default_factory=lambda: os.getenv("SCAN_AZURE_STORAGE", "false").lower() == "true")

    def __post_init__(self):
        """Configure logging after initialization."""
        logging.basicConfig(
            level=getattr(logging, self.log_level.upper()),
            format=self.log_format
        )

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of warnings.

        Returns:
            List of warning messages for missing optional configurations.
        """
        warnings = []

        if self.alerts.enable_sns and not self.aws.sns_topic_arn:
            warnings.append("SNS alerts enabled but AWS_SNS_TOPIC_ARN not set")

        if self.alerts.enable_slack and not self.alerts.slack_webhook_url:
            warnings.append("Slack alerts enabled but SLACK_WEBHOOK_URL not set")

        if self.scan_azure_storage and not self.azure.subscription_id:
            warnings.append("Azure scanning enabled but AZURE_SUBSCRIPTION_ID not set")

        for warning in warnings:
            logger.warning(warning)

        return warnings


# Global configuration instance
config = Config()
