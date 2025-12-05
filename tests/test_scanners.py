# tests/test_scanners.py
"""Tests for CyberMonitor scanners."""

import pytest
from unittest.mock import MagicMock, patch
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cybermonitor.scanners.aws_scanner import AWSScanner, Finding, Severity
from cybermonitor.scanners.terraform_scanner import TerraformScanner


class TestAWSScanner:
    """Tests for AWS Scanner."""

    def test_finding_creation(self):
        """Test that Finding dataclass works correctly."""
        finding = Finding(
            resource_type="AWS::S3::Bucket",
            resource_id="test-bucket",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            remediation="Fix it",
            metadata={"key": "value"}
        )

        assert finding.resource_type == "AWS::S3::Bucket"
        assert finding.resource_id == "test-bucket"
        assert finding.severity == Severity.HIGH
        assert finding.metadata["key"] == "value"

    def test_scanner_initialization(self):
        """Test scanner initializes with empty findings."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)

        assert scanner.findings == []
        assert scanner._boto3 == mock_boto3

    def test_scan_s3_buckets_public_access(self):
        """Test S3 scanner detects public bucket."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)

        # Mock S3 client
        mock_s3 = MagicMock()
        scanner._s3_client = mock_s3

        # Mock responses
        mock_s3.list_buckets.return_value = {
            'Buckets': [{'Name': 'public-bucket'}]
        }
        mock_s3.get_bucket_acl.return_value = {
            'Grants': [{
                'Grantee': {
                    'Type': 'Group',
                    'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                },
                'Permission': 'READ'
            }]
        }

        # Mock public access block check to raise exception (not configured)
        mock_s3.exceptions = MagicMock()
        mock_s3.exceptions.NoSuchPublicAccessBlockConfiguration = Exception
        mock_s3.get_public_access_block.side_effect = Exception("Not configured")

        findings = scanner.scan_s3_buckets()

        assert len(findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("public" in f.title.lower() for f in findings)

    def test_scan_security_groups_open_ssh(self):
        """Test security group scanner detects open SSH."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)

        # Mock EC2 client
        mock_ec2 = MagicMock()
        scanner._ec2_client = mock_ec2

        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'GroupId': 'sg-12345',
                'GroupName': 'test-sg',
                'VpcId': 'vpc-123',
                'IpPermissions': [{
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                    'Ipv6Ranges': []
                }]
            }]
        }

        findings = scanner.scan_security_groups()

        assert len(findings) >= 1
        assert any("SSH" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_scan_iam_admin_policy(self):
        """Test IAM scanner detects admin policy."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)

        # Mock IAM client
        mock_iam = MagicMock()
        scanner._iam_client = mock_iam

        mock_iam.list_users.return_value = {
            'Users': [{
                'UserName': 'admin-user',
                'Arn': 'arn:aws:iam::123456789:user/admin-user'
            }]
        }
        mock_iam.list_attached_user_policies.return_value = {
            'AttachedPolicies': [{
                'PolicyName': 'AdministratorAccess',
                'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
            }]
        }
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}

        findings = scanner.scan_iam_policies()

        assert len(findings) >= 1
        assert any("AdministratorAccess" in f.title for f in findings)

    def test_get_summary(self):
        """Test summary generation."""
        mock_boto3 = MagicMock()
        scanner = AWSScanner(boto3_client=mock_boto3)

        scanner.findings = [
            Finding("type1", "id1", "title1", "desc", Severity.CRITICAL, "fix"),
            Finding("type1", "id2", "title2", "desc", Severity.HIGH, "fix"),
            Finding("type2", "id3", "title3", "desc", Severity.MEDIUM, "fix"),
        ]

        summary = scanner.get_summary()

        assert summary["total"] == 3
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert "type1" in summary["by_resource_type"]
        assert summary["by_resource_type"]["type1"] == 2


class TestTerraformScanner:
    """Tests for Terraform Scanner."""

    def test_scanner_initialization(self):
        """Test Terraform scanner initializes correctly."""
        scanner = TerraformScanner()
        assert scanner.findings == []

    def test_scan_hcl_detects_open_security_group(self):
        """Test Terraform scanner detects open security group."""
        try:
            import hcl2
        except ImportError:
            pytest.skip("python-hcl2 not installed")

        scanner = TerraformScanner()

        hcl_content = '''
resource "aws_security_group" "bad_sg" {
  name = "bad-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        findings = scanner.scan_hcl_content(hcl_content, "test.tf")

        assert len(findings) >= 1
        assert any("SSH" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_scan_hcl_detects_public_s3(self):
        """Test Terraform scanner detects public S3 bucket."""
        try:
            import hcl2
        except ImportError:
            pytest.skip("python-hcl2 not installed")

        scanner = TerraformScanner()

        hcl_content = '''
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
'''
        findings = scanner.scan_hcl_content(hcl_content, "test.tf")

        assert len(findings) >= 1
        assert any("public" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_scan_hcl_detects_public_rds(self):
        """Test Terraform scanner detects publicly accessible RDS."""
        try:
            import hcl2
        except ImportError:
            pytest.skip("python-hcl2 not installed")

        scanner = TerraformScanner()

        hcl_content = '''
resource "aws_db_instance" "public_db" {
  identifier           = "my-db"
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true
}
'''
        findings = scanner.scan_hcl_content(hcl_content, "test.tf")

        assert len(findings) >= 1
        assert any("RDS" in f.title for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_scan_empty_content(self):
        """Test scanner handles empty content."""
        scanner = TerraformScanner()

        try:
            findings = scanner.scan_hcl_content("", "test.tf")
            # Empty content might parse but have no resources
            assert isinstance(findings, list)
        except ImportError:
            pytest.skip("python-hcl2 not installed")


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_comparison(self):
        """Test severity can be compared."""
        assert Severity.CRITICAL == Severity.CRITICAL
        assert Severity.HIGH != Severity.LOW


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
