# cybermonitor/__init__.py
"""
CyberMonitor - Cloud Security Monitoring and Threat Detection System

A comprehensive security monitoring tool for AWS and Azure cloud infrastructure,
comparable to enterprise solutions like Wiz. Features include:

- Multi-cloud security scanning (AWS S3, IAM, EC2, Azure Storage)
- Infrastructure-as-Code security scanning (Terraform)
- Real-time threat detection via CloudTrail
- Behavioral anomaly detection with ML models
- Configurable alerting (SNS, Slack)
"""

__version__ = "1.0.0"
__author__ = "CyberMonitor Team"

from cybermonitor.config import Config
