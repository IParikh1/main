# CyberMonitor - Cost & Resource Estimation

This document provides cost estimates for running CyberMonitor in various deployment scenarios, including AWS API costs for scanning operations.

## Resource Requirements

### Minimum Requirements (Development/Testing)

| Resource | Specification | Notes |
|----------|---------------|-------|
| CPU | 1 core | Lightweight Python application |
| RAM | 512 MB | Minimal for scanning |
| Storage | 1 GB | Logs and configuration |
| Network | 1 Mbps | API calls to AWS/Azure |

### Recommended Requirements (Production)

| Resource | Specification | Notes |
|----------|---------------|-------|
| CPU | 2+ cores | Parallel scanning |
| RAM | 2-4 GB | Large scan results caching |
| Storage | 10 GB SSD | Logs, reports, CloudTrail data |
| Network | 10 Mbps | High-volume API calls |

---

## AWS API Costs (Scanning Operations)

### Per-Scan API Call Estimates

| Service | API Calls per Scan | Free Tier | Cost After Free Tier |
|---------|-------------------|-----------|---------------------|
| S3 | 10-50 | 2,000/month | $0.004 per 1,000 |
| IAM | 5-20 | 1,000/month | $0.01 per 1,000 |
| EC2 | 5-30 | 1,000/month | $0.01 per 1,000 |
| CloudTrail | Varies | N/A | $2.00 per 100,000 events |

**Typical Scan Cost (after free tier):** $0.01 - $0.10 per full scan

### Monthly API Cost Estimates

| Scan Frequency | Scans/Month | Est. API Cost |
|----------------|-------------|---------------|
| Daily | 30 | $0.30 - $3.00 |
| Hourly | 720 | $7.20 - $72.00 |
| Every 15 min | 2,880 | $28.80 - $288.00 |
| Continuous (Lambda) | 10,000+ | $100+ |

---

## CloudTrail Costs (Real-Time Detection)

### CloudTrail Data Events

| Event Type | Cost |
|------------|------|
| Management Events | Free (1 trail) |
| Data Events (S3) | $0.10 per 100,000 events |
| Data Events (Lambda) | $0.10 per 100,000 events |
| CloudTrail Lake | $2.50 per GB ingested |

### Estimated Monthly CloudTrail Costs

| Environment Size | Events/Month | Est. Cost |
|------------------|--------------|-----------|
| Small (10 users) | 100,000 | $0 (free tier) |
| Medium (50 users) | 500,000 | $0.50 |
| Large (200 users) | 2,000,000 | $2.00 |
| Enterprise (1000+ users) | 10,000,000+ | $10.00+ |

---

## Alerting Costs

### AWS SNS

| Metric | Cost |
|--------|------|
| First 1M requests | Free |
| Additional requests | $0.50 per million |
| SMS (US) | $0.00645 per message |
| Email | Free (via SNS) |

### Slack Webhooks

| Tier | Cost |
|------|------|
| Free | $0 (unlimited webhooks) |
| Pro | Part of Slack subscription |

**Typical Monthly Alerting Cost:** $0 - $5

---

## Deployment Cost Estimates

### Option 1: Lambda (Serverless) - Recommended

**Best for:** Event-driven scanning, CloudTrail real-time detection

| Resource | Monthly Cost | Notes |
|----------|--------------|-------|
| Lambda Invocations | $0 - $5 | 1M free/month |
| Lambda Duration | $0 - $10 | 400,000 GB-sec free |
| CloudWatch Logs | $0 - $5 | Log storage |
| S3 (Reports) | $0 - $1 | Report storage |
| **Total** | **$0 - $20/month** | |

**Lambda Configuration:**
```
Memory: 256 MB
Timeout: 60 seconds
Invocations: ~1000/day (scheduled scans)
```

---

### Option 2: EC2 (Always-On Scanner)

#### Small Environment

| Instance | vCPU | RAM | Cost/Month |
|----------|------|-----|------------|
| t3.micro | 2 | 1 GB | ~$8 |
| t3.small | 2 | 2 GB | ~$15 |
| t3.medium | 2 | 4 GB | ~$30 |

**Total with AWS API costs:** $10 - $40/month

#### Medium Environment

| Instance | vCPU | RAM | Cost/Month |
|----------|------|-----|------------|
| t3.large | 2 | 8 GB | ~$60 |
| c6i.large | 2 | 4 GB | ~$61 |

**Total with AWS API costs:** $70 - $150/month

---

### Option 3: ECS Fargate

| Configuration | vCPU | RAM | Cost/Month |
|---------------|------|-----|------------|
| Minimal | 0.25 | 0.5 GB | ~$9 |
| Standard | 0.5 | 1 GB | ~$18 |
| Production | 1 | 2 GB | ~$36 |

**Total with AWS API costs:** $15 - $50/month

---

### Option 4: Kubernetes (EKS)

| Component | Cost/Month |
|-----------|------------|
| EKS Control Plane | $72 |
| Worker Node (t3.medium) | $30 |
| Load Balancer | $16 |
| **Minimum Total** | **$118/month** |

*Note: Overkill for most CyberMonitor deployments*

---

## Multi-Cloud Scanning Costs

### Azure API Costs

| Service | API Calls | Cost |
|---------|-----------|------|
| Storage Accounts | Free tier | $0 |
| Resource Graph | 1000/5 sec limit | $0 |
| Management APIs | Generally free | $0 |

**Azure scanning adds minimal cost** - most APIs are free

### Cross-Cloud Architecture

| Component | AWS Cost | Azure Cost | Total |
|-----------|----------|------------|-------|
| Scanner (Lambda) | $10 | N/A | $10 |
| Azure Function | N/A | $5 | $5 |
| Results Storage | $2 | $2 | $4 |
| Alerting | $2 | $0 | $2 |
| **Total** | | | **$21/month** |

---

## Cost by Use Case

### Use Case 1: Single AWS Account (Hobby/Startup)

| Component | Cost |
|-----------|------|
| Lambda Scanner | $0 (free tier) |
| CloudTrail (mgmt events) | $0 (1 free trail) |
| SNS Alerts | $0 (free tier) |
| CloudWatch Logs | $0 - $2 |
| **Total** | **$0 - $2/month** |

### Use Case 2: Small Business (5-10 AWS Accounts)

| Component | Cost |
|-----------|------|
| Lambda Scanner | $5 |
| CloudTrail | $5 |
| SNS/Slack Alerts | $2 |
| S3 Reports | $1 |
| CloudWatch | $5 |
| **Total** | **$15 - $25/month** |

### Use Case 3: Enterprise (50+ AWS Accounts)

| Component | Cost |
|-----------|------|
| EC2 Scanner (t3.large) | $60 |
| CloudTrail (all accounts) | $50 |
| SNS Alerts | $10 |
| S3 Reports | $5 |
| CloudWatch | $20 |
| Cross-account roles | $0 |
| **Total** | **$150 - $200/month** |

---

## Comparison with Commercial Solutions

| Solution | Monthly Cost | Notes |
|----------|--------------|-------|
| **CyberMonitor (Self-Hosted)** | $0 - $200 | Open source, full control |
| Wiz | $5,000+ | Enterprise CSPM |
| Prowler (Self-Hosted) | $0 - $100 | Open source alternative |
| AWS Security Hub | $0.0010/check | Native AWS |
| Prisma Cloud | $3,000+ | Enterprise CNAPP |
| Lacework | $10,000+ | Enterprise cloud security |

**CyberMonitor provides 80% of enterprise features at <5% of the cost**

---

## Cost Optimization Tips

### 1. Use Lambda for Scheduled Scans
```python
# Scan every 6 hours instead of hourly
rate(6 hours)  # 120 invocations/month vs 720
```

### 2. Aggregate CloudTrail Logs
- Use S3 lifecycle policies to move logs to Glacier
- Saves 80% on long-term storage

### 3. Filter CloudTrail Events
```python
# Only capture relevant events
event_selectors = [
    {"ReadWriteType": "WriteOnly"}  # Skip read events
]
```

### 4. Use Reserved Capacity
- EC2 Reserved Instances: 30-40% savings
- Savings Plans: Up to 72% savings

### 5. Right-Size Resources
- Start with t3.micro, scale up only if needed
- Monitor with CloudWatch to identify over-provisioning

---

## Sample Budgets

### Budget: $0/month (Free Tier)
- Lambda for scanning (1M invocations free)
- 1 CloudTrail trail (free)
- SNS email alerts (free)
- Best for: Learning, single account

### Budget: $25/month
- Lambda with increased invocations
- CloudTrail with data events
- S3 for report storage
- Best for: Small teams, 1-5 accounts

### Budget: $100/month
- EC2 t3.medium always-on scanner
- Multi-account CloudTrail
- Slack + SNS alerts
- Best for: Growing companies, 5-20 accounts

### Budget: $500/month
- EC2 c6i.large dedicated scanner
- Full CloudTrail Lake integration
- Multiple alert channels
- Historical data retention
- Best for: Enterprise, 20-100 accounts

---

## IAM Permissions (No Additional Cost)

CyberMonitor requires these IAM permissions (no cost):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketPublicAccessBlock",
        "ec2:DescribeSecurityGroups",
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "iam:ListMFADevices",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## TCO Calculator

```
Monthly Cost = Compute + AWS APIs + CloudTrail + Alerting + Storage

Example (Medium deployment):
- Compute (Lambda): $10
- AWS API calls: $5
- CloudTrail events: $10
- SNS Alerts: $2
- S3 Storage: $3
- CloudWatch: $5
- Total: ~$35/month

vs. Commercial CSPM: $5,000+/month
Savings: 99.3%
```

---

*Last updated: December 2024*
*Prices are estimates based on AWS US-East-1 region*
*Actual costs may vary by region and usage patterns*
