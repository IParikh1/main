# cybermonitor/scanners/terraform_scanner.py
"""
Terraform/Infrastructure-as-Code Security Scanner.

Scans Terraform files for security misconfigurations before deployment.
Similar to tools like tfsec, checkov, and Wiz's IaC scanning.

Checks:
- Open security group rules
- Public S3 buckets
- Unencrypted resources
- Missing logging configurations
"""

import logging
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from cybermonitor.scanners.aws_scanner import Finding, Severity

logger = logging.getLogger(__name__)


class TerraformScanner:
    """
    Terraform Security Scanner for detecting misconfigurations in IaC.

    Scans .tf files for common security issues before deployment.
    """

    def __init__(self):
        """Initialize the Terraform scanner."""
        self.findings: List[Finding] = []
        self._hcl2 = None

    @property
    def hcl2(self):
        """Lazy load hcl2 parser."""
        if self._hcl2 is None:
            try:
                import hcl2
                self._hcl2 = hcl2
            except ImportError:
                raise ImportError(
                    "python-hcl2 is required for Terraform scanning. "
                    "Install with: pip install python-hcl2"
                )
        return self._hcl2

    def scan_file(self, file_path: Union[str, Path]) -> List[Finding]:
        """
        Scan a single Terraform file.

        Args:
            file_path: Path to the .tf file

        Returns:
            List of security findings
        """
        file_path = Path(file_path)
        logger.info(f"Scanning Terraform file: {file_path}")

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        if not file_path.suffix == '.tf':
            logger.warning(f"File {file_path} is not a .tf file")
            return []

        try:
            with open(file_path, 'r') as f:
                config = self.hcl2.load(f)

            findings = []
            findings.extend(self._check_security_groups(config, str(file_path)))
            findings.extend(self._check_s3_buckets(config, str(file_path)))
            findings.extend(self._check_rds_instances(config, str(file_path)))
            findings.extend(self._check_ec2_instances(config, str(file_path)))

            self.findings.extend(findings)
            return findings

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return []

    def scan_directory(self, directory: Union[str, Path]) -> List[Finding]:
        """
        Scan all Terraform files in a directory.

        Args:
            directory: Path to directory containing .tf files

        Returns:
            List of security findings
        """
        directory = Path(directory)
        logger.info(f"Scanning Terraform directory: {directory}")

        if not directory.exists():
            logger.error(f"Directory not found: {directory}")
            return []

        all_findings = []
        tf_files = list(directory.glob("**/*.tf"))

        logger.info(f"Found {len(tf_files)} Terraform files")

        for tf_file in tf_files:
            findings = self.scan_file(tf_file)
            all_findings.extend(findings)

        return all_findings

    def scan_hcl_content(self, content: str, source: str = "inline") -> List[Finding]:
        """
        Scan HCL content directly (for testing or API usage).

        Args:
            content: HCL/Terraform content as string
            source: Source identifier for findings

        Returns:
            List of security findings
        """
        try:
            import io
            config = self.hcl2.load(io.StringIO(content))

            findings = []
            findings.extend(self._check_security_groups(config, source))
            findings.extend(self._check_s3_buckets(config, source))
            findings.extend(self._check_rds_instances(config, source))
            findings.extend(self._check_ec2_instances(config, source))

            self.findings.extend(findings)
            return findings

        except Exception as e:
            logger.error(f"Error parsing HCL content: {e}")
            return []

    def _check_security_groups(self, config: Dict, source: str) -> List[Finding]:
        """Check for overly permissive security group rules."""
        findings = []
        resources = config.get('resource', [])

        # Handle both list and dict formats
        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            # Check aws_security_group
            for sg_name, sg_configs in resource_block.get('aws_security_group', {}).items():
                if isinstance(sg_configs, list):
                    sg_configs = sg_configs[0] if sg_configs else {}

                # Check ingress rules
                ingress_rules = sg_configs.get('ingress', [])
                if isinstance(ingress_rules, dict):
                    ingress_rules = [ingress_rules]

                for rule in ingress_rules:
                    if isinstance(rule, dict):
                        cidr_blocks = rule.get('cidr_blocks', [])
                        from_port = rule.get('from_port', 0)
                        to_port = rule.get('to_port', 65535)
                        protocol = rule.get('protocol', '-1')

                        if '0.0.0.0/0' in cidr_blocks:
                            # All traffic open
                            if protocol == '-1':
                                findings.append(Finding(
                                    resource_type="Terraform::AWS::SecurityGroup",
                                    resource_id=f"{source}:{sg_name}",
                                    title="Security Group Allows All Inbound Traffic",
                                    description=f"Security group '{sg_name}' allows all traffic from any IP",
                                    severity=Severity.CRITICAL,
                                    remediation="Restrict ingress rules to specific IPs and ports",
                                    metadata={"file": source, "resource": sg_name}
                                ))

                            # SSH open to internet
                            if from_port <= 22 <= to_port:
                                findings.append(Finding(
                                    resource_type="Terraform::AWS::SecurityGroup",
                                    resource_id=f"{source}:{sg_name}",
                                    title="Security Group Exposes SSH to Internet",
                                    description=f"Security group '{sg_name}' allows SSH (port 22) from any IP",
                                    severity=Severity.CRITICAL,
                                    remediation="Restrict SSH access to specific IP ranges or use a bastion host",
                                    metadata={"file": source, "resource": sg_name, "port": 22}
                                ))

                            # RDP open to internet
                            if from_port <= 3389 <= to_port:
                                findings.append(Finding(
                                    resource_type="Terraform::AWS::SecurityGroup",
                                    resource_id=f"{source}:{sg_name}",
                                    title="Security Group Exposes RDP to Internet",
                                    description=f"Security group '{sg_name}' allows RDP (port 3389) from any IP",
                                    severity=Severity.CRITICAL,
                                    remediation="Restrict RDP access to specific IP ranges",
                                    metadata={"file": source, "resource": sg_name, "port": 3389}
                                ))

                            # Database ports open
                            db_ports = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}
                            for port, db_name in db_ports.items():
                                if from_port <= port <= to_port:
                                    findings.append(Finding(
                                        resource_type="Terraform::AWS::SecurityGroup",
                                        resource_id=f"{source}:{sg_name}",
                                        title=f"Security Group Exposes {db_name} to Internet",
                                        description=f"Security group '{sg_name}' allows {db_name} (port {port}) from any IP",
                                        severity=Severity.HIGH,
                                        remediation=f"Restrict {db_name} access to application subnets only",
                                        metadata={"file": source, "resource": sg_name, "port": port}
                                    ))

        return findings

    def _check_s3_buckets(self, config: Dict, source: str) -> List[Finding]:
        """Check for insecure S3 bucket configurations."""
        findings = []
        resources = config.get('resource', [])

        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            for bucket_name, bucket_configs in resource_block.get('aws_s3_bucket', {}).items():
                if isinstance(bucket_configs, list):
                    bucket_configs = bucket_configs[0] if bucket_configs else {}

                # Check for public ACL
                acl = bucket_configs.get('acl', 'private')
                if acl in ['public-read', 'public-read-write']:
                    findings.append(Finding(
                        resource_type="Terraform::AWS::S3Bucket",
                        resource_id=f"{source}:{bucket_name}",
                        title="S3 Bucket Has Public ACL",
                        description=f"S3 bucket '{bucket_name}' has a public ACL ({acl})",
                        severity=Severity.CRITICAL,
                        remediation="Remove public ACL and use bucket policies with specific principals",
                        metadata={"file": source, "resource": bucket_name, "acl": acl}
                    ))

            # Check aws_s3_bucket_public_access_block
            for block_name, block_configs in resource_block.get('aws_s3_bucket_public_access_block', {}).items():
                if isinstance(block_configs, list):
                    block_configs = block_configs[0] if block_configs else {}

                checks = [
                    'block_public_acls',
                    'block_public_policy',
                    'ignore_public_acls',
                    'restrict_public_buckets'
                ]

                for check in checks:
                    if not block_configs.get(check, True):
                        findings.append(Finding(
                            resource_type="Terraform::AWS::S3BucketPublicAccessBlock",
                            resource_id=f"{source}:{block_name}",
                            title=f"S3 Block Public Access: {check} Disabled",
                            description=f"Public access block '{block_name}' has {check} disabled",
                            severity=Severity.MEDIUM,
                            remediation=f"Set {check} = true",
                            metadata={"file": source, "resource": block_name, "setting": check}
                        ))

        return findings

    def _check_rds_instances(self, config: Dict, source: str) -> List[Finding]:
        """Check for insecure RDS configurations."""
        findings = []
        resources = config.get('resource', [])

        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            for rds_name, rds_configs in resource_block.get('aws_db_instance', {}).items():
                if isinstance(rds_configs, list):
                    rds_configs = rds_configs[0] if rds_configs else {}

                # Check public accessibility
                if rds_configs.get('publicly_accessible', False):
                    findings.append(Finding(
                        resource_type="Terraform::AWS::RDSInstance",
                        resource_id=f"{source}:{rds_name}",
                        title="RDS Instance Publicly Accessible",
                        description=f"RDS instance '{rds_name}' is publicly accessible",
                        severity=Severity.CRITICAL,
                        remediation="Set publicly_accessible = false and use VPC private subnets",
                        metadata={"file": source, "resource": rds_name}
                    ))

                # Check encryption
                if not rds_configs.get('storage_encrypted', False):
                    findings.append(Finding(
                        resource_type="Terraform::AWS::RDSInstance",
                        resource_id=f"{source}:{rds_name}",
                        title="RDS Instance Not Encrypted",
                        description=f"RDS instance '{rds_name}' does not have storage encryption enabled",
                        severity=Severity.HIGH,
                        remediation="Set storage_encrypted = true and specify a KMS key",
                        metadata={"file": source, "resource": rds_name}
                    ))

                # Check backup retention
                backup_retention = rds_configs.get('backup_retention_period', 0)
                if backup_retention == 0:
                    findings.append(Finding(
                        resource_type="Terraform::AWS::RDSInstance",
                        resource_id=f"{source}:{rds_name}",
                        title="RDS Instance Has No Backup Retention",
                        description=f"RDS instance '{rds_name}' has backup retention disabled",
                        severity=Severity.MEDIUM,
                        remediation="Set backup_retention_period to at least 7 days",
                        metadata={"file": source, "resource": rds_name}
                    ))

        return findings

    def _check_ec2_instances(self, config: Dict, source: str) -> List[Finding]:
        """Check for insecure EC2 configurations."""
        findings = []
        resources = config.get('resource', [])

        if isinstance(resources, dict):
            resources = [resources]

        for resource_block in resources:
            for instance_name, instance_configs in resource_block.get('aws_instance', {}).items():
                if isinstance(instance_configs, list):
                    instance_configs = instance_configs[0] if instance_configs else {}

                # Check IMDSv2 enforcement
                metadata_options = instance_configs.get('metadata_options', {})
                if isinstance(metadata_options, list):
                    metadata_options = metadata_options[0] if metadata_options else {}

                http_tokens = metadata_options.get('http_tokens', 'optional')
                if http_tokens != 'required':
                    findings.append(Finding(
                        resource_type="Terraform::AWS::EC2Instance",
                        resource_id=f"{source}:{instance_name}",
                        title="EC2 Instance Does Not Require IMDSv2",
                        description=f"EC2 instance '{instance_name}' does not enforce IMDSv2",
                        severity=Severity.MEDIUM,
                        remediation="Set metadata_options.http_tokens = 'required'",
                        metadata={"file": source, "resource": instance_name}
                    ))

                # Check EBS encryption
                root_block = instance_configs.get('root_block_device', {})
                if isinstance(root_block, list):
                    root_block = root_block[0] if root_block else {}

                if not root_block.get('encrypted', False):
                    findings.append(Finding(
                        resource_type="Terraform::AWS::EC2Instance",
                        resource_id=f"{source}:{instance_name}",
                        title="EC2 Root Volume Not Encrypted",
                        description=f"EC2 instance '{instance_name}' root volume is not encrypted",
                        severity=Severity.MEDIUM,
                        remediation="Set root_block_device.encrypted = true",
                        metadata={"file": source, "resource": instance_name}
                    ))

        return findings

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of scan findings."""
        summary = {
            "total": len(self.findings),
            "by_severity": {
                Severity.CRITICAL.value: 0,
                Severity.HIGH.value: 0,
                Severity.MEDIUM.value: 0,
                Severity.LOW.value: 0,
                Severity.INFO.value: 0
            }
        }

        for finding in self.findings:
            summary["by_severity"][finding.severity.value] += 1

        return summary
