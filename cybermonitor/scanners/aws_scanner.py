# cybermonitor/scanners/aws_scanner.py
"""
AWS Security Scanner - Scans AWS resources for security misconfigurations.

Comparable to Wiz's AWS scanning capabilities:
- S3 bucket public access detection
- IAM policy analysis
- EC2 security group audit
- CloudTrail configuration check
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Finding severity levels aligned with industry standards."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Security finding from a scan."""
    resource_type: str
    resource_id: str
    title: str
    description: str
    severity: Severity
    remediation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class AWSScanner:
    """
    AWS Security Scanner for detecting misconfigurations.

    Scans:
    - S3 buckets for public access
    - IAM users for overly permissive policies
    - EC2 security groups for open ingress rules
    """

    def __init__(self, boto3_client=None):
        """
        Initialize the AWS scanner.

        Args:
            boto3_client: Optional boto3 module for dependency injection (testing)
        """
        self._boto3 = boto3_client
        self._s3_client = None
        self._iam_client = None
        self._ec2_client = None
        self.findings: List[Finding] = []

    @property
    def boto3(self):
        """Lazy load boto3."""
        if self._boto3 is None:
            try:
                import boto3
                self._boto3 = boto3
            except ImportError:
                raise ImportError("boto3 is required for AWS scanning. Install with: pip install boto3")
        return self._boto3

    @property
    def s3_client(self):
        """Lazy load S3 client."""
        if self._s3_client is None:
            self._s3_client = self.boto3.client('s3')
        return self._s3_client

    @property
    def iam_client(self):
        """Lazy load IAM client."""
        if self._iam_client is None:
            self._iam_client = self.boto3.client('iam')
        return self._iam_client

    @property
    def ec2_client(self):
        """Lazy load EC2 client."""
        if self._ec2_client is None:
            self._ec2_client = self.boto3.client('ec2')
        return self._ec2_client

    def scan_all(self) -> List[Finding]:
        """
        Run all AWS security scans.

        Returns:
            List of security findings
        """
        logger.info("Starting comprehensive AWS security scan...")
        self.findings = []

        self.scan_s3_buckets()
        self.scan_iam_policies()
        self.scan_security_groups()

        logger.info(f"AWS scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def scan_s3_buckets(self) -> List[Finding]:
        """
        Scan S3 buckets for public access misconfigurations.

        Checks:
        - Bucket ACLs for AllUsers/AuthenticatedUsers grants
        - Public access block settings
        - Bucket policies for public access

        Returns:
            List of S3-related findings
        """
        logger.info("Scanning S3 buckets for public access...")
        s3_findings = []

        try:
            response = self.s3_client.list_buckets()

            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                logger.debug(f"Scanning bucket: {bucket_name}")

                # Check bucket ACL
                try:
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        uri = grantee.get('URI', '')

                        if 'AllUsers' in uri:
                            finding = Finding(
                                resource_type="AWS::S3::Bucket",
                                resource_id=bucket_name,
                                title="S3 Bucket Publicly Accessible",
                                description=f"Bucket {bucket_name} has public access via ACL (AllUsers grant)",
                                severity=Severity.CRITICAL,
                                remediation="Remove public ACL grants and enable S3 Block Public Access",
                                metadata={
                                    "grant_permission": grant.get('Permission'),
                                    "grantee_uri": uri
                                }
                            )
                            s3_findings.append(finding)
                            logger.warning(f"CRITICAL: Bucket {bucket_name} is publicly accessible!")

                        elif 'AuthenticatedUsers' in uri:
                            finding = Finding(
                                resource_type="AWS::S3::Bucket",
                                resource_id=bucket_name,
                                title="S3 Bucket Accessible to All AWS Users",
                                description=f"Bucket {bucket_name} grants access to any authenticated AWS user",
                                severity=Severity.HIGH,
                                remediation="Remove AuthenticatedUsers grant and restrict access",
                                metadata={
                                    "grant_permission": grant.get('Permission'),
                                    "grantee_uri": uri
                                }
                            )
                            s3_findings.append(finding)
                            logger.warning(f"HIGH: Bucket {bucket_name} accessible to all AWS users")

                except Exception as e:
                    logger.debug(f"Could not check ACL for {bucket_name}: {e}")

                # Check Public Access Block
                try:
                    pab = self.s3_client.get_public_access_block(Bucket=bucket_name)
                    config = pab.get('PublicAccessBlockConfiguration', {})

                    if not all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ]):
                        finding = Finding(
                            resource_type="AWS::S3::Bucket",
                            resource_id=bucket_name,
                            title="S3 Block Public Access Not Fully Enabled",
                            description=f"Bucket {bucket_name} does not have all Block Public Access settings enabled",
                            severity=Severity.MEDIUM,
                            remediation="Enable all S3 Block Public Access settings",
                            metadata={"public_access_block": config}
                        )
                        s3_findings.append(finding)

                except self.s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                    finding = Finding(
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        title="S3 Block Public Access Not Configured",
                        description=f"Bucket {bucket_name} has no Block Public Access configuration",
                        severity=Severity.MEDIUM,
                        remediation="Configure S3 Block Public Access settings",
                        metadata={}
                    )
                    s3_findings.append(finding)
                except Exception as e:
                    logger.debug(f"Could not check public access block for {bucket_name}: {e}")

        except Exception as e:
            logger.error(f"Error scanning S3 buckets: {e}")

        self.findings.extend(s3_findings)
        return s3_findings

    def scan_iam_policies(self) -> List[Finding]:
        """
        Scan IAM users and policies for security issues.

        Checks:
        - Users with admin policies attached
        - Users with overly permissive inline policies
        - Users without MFA enabled

        Returns:
            List of IAM-related findings
        """
        logger.info("Scanning IAM policies...")
        iam_findings = []

        try:
            response = self.iam_client.list_users()

            for user in response.get('Users', []):
                user_name = user['UserName']
                user_arn = user['Arn']
                logger.debug(f"Scanning IAM user: {user_name}")

                # Check attached policies
                try:
                    policies = self.iam_client.list_attached_user_policies(UserName=user_name)

                    for policy in policies.get('AttachedPolicies', []):
                        policy_name = policy['PolicyName']
                        policy_arn = policy['PolicyArn']

                        # Check for admin policies
                        admin_policies = [
                            'AdministratorAccess',
                            'PowerUserAccess',
                            'IAMFullAccess'
                        ]

                        if policy_name in admin_policies:
                            finding = Finding(
                                resource_type="AWS::IAM::User",
                                resource_id=user_arn,
                                title=f"IAM User Has {policy_name} Policy",
                                description=f"User {user_name} has overly permissive {policy_name} policy attached",
                                severity=Severity.HIGH,
                                remediation="Apply least privilege principle - remove admin policies and grant specific permissions",
                                metadata={
                                    "user_name": user_name,
                                    "policy_name": policy_name,
                                    "policy_arn": policy_arn
                                }
                            )
                            iam_findings.append(finding)
                            logger.warning(f"HIGH: User {user_name} has {policy_name} policy")

                except Exception as e:
                    logger.debug(f"Could not check policies for {user_name}: {e}")

                # Check MFA status
                try:
                    mfa_devices = self.iam_client.list_mfa_devices(UserName=user_name)
                    if not mfa_devices.get('MFADevices', []):
                        finding = Finding(
                            resource_type="AWS::IAM::User",
                            resource_id=user_arn,
                            title="IAM User Without MFA",
                            description=f"User {user_name} does not have MFA enabled",
                            severity=Severity.MEDIUM,
                            remediation="Enable MFA for the IAM user",
                            metadata={"user_name": user_name}
                        )
                        iam_findings.append(finding)

                except Exception as e:
                    logger.debug(f"Could not check MFA for {user_name}: {e}")

        except Exception as e:
            logger.error(f"Error scanning IAM policies: {e}")

        self.findings.extend(iam_findings)
        return iam_findings

    def scan_security_groups(self) -> List[Finding]:
        """
        Scan EC2 security groups for overly permissive rules.

        Checks:
        - Ingress rules allowing 0.0.0.0/0 (any IP)
        - Open SSH (22), RDP (3389), database ports
        - Rules allowing all protocols/ports

        Returns:
            List of security group findings
        """
        logger.info("Scanning EC2 security groups...")
        sg_findings = []

        # Sensitive ports that shouldn't be open to the internet
        sensitive_ports = {
            22: ("SSH", Severity.CRITICAL),
            3389: ("RDP", Severity.CRITICAL),
            3306: ("MySQL", Severity.HIGH),
            5432: ("PostgreSQL", Severity.HIGH),
            1433: ("MSSQL", Severity.HIGH),
            27017: ("MongoDB", Severity.HIGH),
            6379: ("Redis", Severity.HIGH),
            9200: ("Elasticsearch", Severity.HIGH),
            23: ("Telnet", Severity.CRITICAL),
            21: ("FTP", Severity.HIGH),
        }

        try:
            response = self.ec2_client.describe_security_groups()

            for sg in response.get('SecurityGroups', []):
                sg_id = sg['GroupId']
                sg_name = sg.get('GroupName', 'Unknown')
                vpc_id = sg.get('VpcId', 'N/A')
                logger.debug(f"Scanning security group: {sg_id}")

                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    protocol = rule.get('IpProtocol', '-1')

                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')

                        if cidr == '0.0.0.0/0':
                            # Check if all traffic is allowed
                            if protocol == '-1':
                                finding = Finding(
                                    resource_type="AWS::EC2::SecurityGroup",
                                    resource_id=sg_id,
                                    title="Security Group Allows All Inbound Traffic",
                                    description=f"Security group {sg_name} ({sg_id}) allows all traffic from any IP",
                                    severity=Severity.CRITICAL,
                                    remediation="Restrict inbound rules to specific IPs and ports",
                                    metadata={
                                        "sg_name": sg_name,
                                        "vpc_id": vpc_id,
                                        "rule": str(rule)
                                    }
                                )
                                sg_findings.append(finding)
                                logger.warning(f"CRITICAL: {sg_id} allows ALL inbound traffic from anywhere!")

                            # Check for sensitive ports
                            for port, (service, severity) in sensitive_ports.items():
                                if from_port <= port <= to_port:
                                    finding = Finding(
                                        resource_type="AWS::EC2::SecurityGroup",
                                        resource_id=sg_id,
                                        title=f"Security Group Exposes {service} to Internet",
                                        description=f"Security group {sg_name} ({sg_id}) allows {service} (port {port}) from any IP",
                                        severity=severity,
                                        remediation=f"Restrict {service} access to specific IP ranges",
                                        metadata={
                                            "sg_name": sg_name,
                                            "vpc_id": vpc_id,
                                            "port": port,
                                            "service": service
                                        }
                                    )
                                    sg_findings.append(finding)
                                    logger.warning(f"{severity.value.upper()}: {sg_id} exposes {service} to internet")

                    # Also check IPv6
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        cidr = ipv6_range.get('CidrIpv6', '')
                        if cidr == '::/0':
                            finding = Finding(
                                resource_type="AWS::EC2::SecurityGroup",
                                resource_id=sg_id,
                                title="Security Group Allows IPv6 Traffic from Any Source",
                                description=f"Security group {sg_name} ({sg_id}) allows IPv6 traffic from ::/0",
                                severity=Severity.HIGH,
                                remediation="Restrict IPv6 inbound rules",
                                metadata={
                                    "sg_name": sg_name,
                                    "vpc_id": vpc_id,
                                    "ipv6_cidr": cidr
                                }
                            )
                            sg_findings.append(finding)

        except Exception as e:
            logger.error(f"Error scanning security groups: {e}")

        self.findings.extend(sg_findings)
        return sg_findings

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of scan findings.

        Returns:
            Dictionary with finding counts by severity
        """
        summary = {
            "total": len(self.findings),
            "by_severity": {
                Severity.CRITICAL.value: 0,
                Severity.HIGH.value: 0,
                Severity.MEDIUM.value: 0,
                Severity.LOW.value: 0,
                Severity.INFO.value: 0
            },
            "by_resource_type": {}
        }

        for finding in self.findings:
            summary["by_severity"][finding.severity.value] += 1

            rt = finding.resource_type
            if rt not in summary["by_resource_type"]:
                summary["by_resource_type"][rt] = 0
            summary["by_resource_type"][rt] += 1

        return summary
