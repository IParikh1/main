# CyberMonitor

A comprehensive cloud security monitoring and threat detection system for AWS and Azure infrastructure, comparable to enterprise solutions like Wiz.

## Features

- **Multi-Cloud Security Scanning**
  - AWS: S3 buckets, IAM policies, EC2 security groups
  - Azure: Storage accounts, network security
  - Infrastructure-as-Code: Terraform file scanning

- **Real-Time Threat Detection**
  - CloudTrail event analysis
  - Suspicious region detection
  - Behavioral anomaly detection
  - Sensitive action monitoring

- **Alerting**
  - AWS SNS integration
  - Slack webhook notifications
  - Console logging

- **Severity Classification**
  - Critical, High, Medium, Low, Info levels
  - Remediation guidance for each finding

## Installation

```bash
# Clone the repository
git clone https://github.com/IParikh1/main.git
cd main

# Install dependencies
pip install -r requirements.txt

# For AWS scanning
pip install boto3

# For Azure scanning
pip install azure-identity azure-mgmt-storage

# For Terraform scanning
pip install python-hcl2
```

## Quick Start

### AWS Scanning

```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_REGION=us-east-1

# Run scan
python -m cybermonitor.cli scan aws
```

### Azure Scanning

```bash
# Configure Azure credentials
export AZURE_SUBSCRIPTION_ID=your_subscription_id
export AZURE_TENANT_ID=your_tenant_id
export AZURE_CLIENT_ID=your_client_id
export AZURE_CLIENT_SECRET=your_secret

# Run scan
python -m cybermonitor.cli scan azure
```

### Terraform Scanning

```bash
# Scan a directory
python -m cybermonitor.cli scan terraform --path ./infrastructure

# Scan a single file
python -m cybermonitor.cli scan terraform --path ./main.tf
```

### Run All Scans

```bash
python -m cybermonitor.cli scan all --output report.json --format json
```

## Configuration

CyberMonitor uses environment variables for configuration:

### AWS Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region | us-east-1 |
| `AWS_SNS_TOPIC_ARN` | SNS topic for alerts | - |
| `AWS_CLOUDTRAIL_BUCKET` | CloudTrail log bucket | - |

### Azure Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID | - |
| `AZURE_TENANT_ID` | Azure tenant ID | - |
| `AZURE_CLIENT_ID` | Azure client ID | - |

### Alerting Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `SLACK_WEBHOOK_URL` | Slack webhook URL | - |
| `ENABLE_SNS_ALERTS` | Enable SNS alerts | true |
| `ENABLE_SLACK_ALERTS` | Enable Slack alerts | false |

### Scanning Configuration
| Variable | Description | Default |
|----------|-------------|---------|
| `SCAN_S3` | Enable S3 scanning | true |
| `SCAN_IAM` | Enable IAM scanning | true |
| `SCAN_EC2` | Enable EC2 scanning | true |
| `SCAN_AZURE_STORAGE` | Enable Azure storage scanning | false |
| `LOG_LEVEL` | Logging level | INFO |

## CLI Usage

```bash
# Show help
python -m cybermonitor.cli --help

# Show version
python -m cybermonitor.cli --version

# AWS scan with alerts
python -m cybermonitor.cli scan aws --alert

# Terraform scan with JSON output
python -m cybermonitor.cli scan terraform --path ./tf --output findings.json --format json

# Verbose mode
python -m cybermonitor.cli -v scan all
```

## Security Checks

### AWS Checks
- **S3 Buckets**
  - Public access via ACL (AllUsers, AuthenticatedUsers)
  - Block Public Access configuration
  - Bucket policies with public access

- **IAM**
  - Users with AdministratorAccess policy
  - Users without MFA enabled
  - Overly permissive policies

- **EC2 Security Groups**
  - Open SSH (22) to internet
  - Open RDP (3389) to internet
  - Open database ports (3306, 5432, 1433, 27017)
  - All traffic allowed from 0.0.0.0/0

### Azure Checks
- **Storage Accounts**
  - Public network access enabled
  - Blob public access allowed
  - HTTPS not enforced
  - TLS version below 1.2

### Terraform Checks
- Security groups with open ingress rules
- S3 buckets with public ACLs
- RDS instances that are publicly accessible
- Unencrypted RDS storage
- EC2 instances without IMDSv2

## Lambda Deployment

CyberMonitor includes a Lambda handler for real-time CloudTrail monitoring:

```python
from cybermonitor.detectors.cloudtrail_detector import CloudTrailDetector

detector = CloudTrailDetector()

def lambda_handler(event, context):
    return detector.lambda_handler(event, context)
```

Deploy to Lambda and configure:
1. Create an IAM role with CloudTrail read and SNS publish permissions
2. Set up S3 event notification to trigger on CloudTrail log delivery
3. Configure environment variables for alerting

## Project Structure

```
cybermonitor/
├── __init__.py           # Package initialization
├── config.py             # Configuration management
├── cli.py                # Command-line interface
├── scanners/
│   ├── aws_scanner.py    # AWS security scanning
│   ├── azure_scanner.py  # Azure security scanning
│   └── terraform_scanner.py  # IaC scanning
├── detectors/
│   └── cloudtrail_detector.py  # Real-time detection
├── alerting/
│   ├── alert_manager.py  # Unified alerting
│   ├── sns_alert.py      # AWS SNS alerts
│   └── slack_alert.py    # Slack alerts
└── utils/
    └── formatters.py     # Output formatting
```

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-mock

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=cybermonitor
```

## Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║  CyberMonitor v1.0.0                                          ║
║  Cloud Security Scanning Tool                                 ║
╚═══════════════════════════════════════════════════════════════╝

[*] Starting AWS Security Scan...

================================================================================
SECURITY FINDINGS
================================================================================

[CRITICAL] (2 findings)
----------------------------------------
  * S3 Bucket Publicly Accessible
    Resource: my-public-bucket
    Bucket my-public-bucket has public access via ACL (AllUsers grant)
    Remediation: Remove public ACL grants and enable S3 Block Public Access

  * Security Group Exposes SSH to Internet
    Resource: sg-12345678
    Security group allows SSH (port 22) from any IP
    Remediation: Restrict SSH access to specific IP ranges or use a bastion host

[HIGH] (1 findings)
----------------------------------------
  * IAM User Has AdministratorAccess Policy
    Resource: arn:aws:iam::123456789:user/admin-user
    User admin-user has overly permissive AdministratorAccess policy attached
    Remediation: Apply least privilege principle - remove admin policies

==================================================
SCAN SUMMARY
==================================================
Total Findings: 3

By Severity:
  CRITICAL: 2
  HIGH: 1
==================================================

[!] Found 3 critical/high severity issues!
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Inspired by cloud security tools like Wiz, Prowler, and ScoutSuite
- Built with Python and boto3/Azure SDK
