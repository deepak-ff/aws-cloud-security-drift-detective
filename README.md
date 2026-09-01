# 🔒 Security-Compliance-Guardrail-Lab

![AWS](https://img.shields.io/badge/AWS-%23FF9900.svg?style=for-the-badge&logo=amazon-aws&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Terraform](https://img.shields.io/badge/terraform-%235835CC.svg?style=for-the-badge&logo=terraform&logoColor=white)
![Security](https://img.shields.io/badge/Security-Critical-red?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)

> **Hands-on AWS security lab demonstrating real-world misconfiguration detection, automated remediation, and compliance enforcement—built to showcase cloud security skills for entry-level DevOps and Cloud Engineering roles.**

---

## 🎯 Project Overview

This lab simulates a production AWS environment where security misconfigurations are intentionally introduced and then detected and remediated using automated guardrails. It demonstrates practical knowledge of:

- **AWS Security Best Practices** - IAM policies, S3 bucket security, encryption enforcement
- **Automated Compliance** - Event-driven remediation using Lambda and CloudWatch
- **Incident Response** - CloudTrail logging, alerting, and forensic analysis
- **Infrastructure as Code** - Terraform deployment and configuration management
- **Preventative CloudOps** - Proactive security controls and monitoring

**Perfect for**: Cloud Security roles, DevOps positions, Cloud Operations, and entry-level AWS jobs requiring security awareness.

---

## 🏗️ Architecture

```
┌─────────────────┐
│   CloudTrail    │──► Logs all API calls
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  EventBridge    │──► Detects misconfigurations
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Lambda Function│──► Auto-remediates issues
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SNS Alerts     │──► Notifies security team
└─────────────────┘
```

### Monitored Resources:
- **S3 Buckets** - Public access, encryption status, versioning
- **IAM Users** - Overly permissive policies, unused credentials
- **EC2 Instances** - Security group misconfigurations, missing tags
- **RDS Databases** - Public accessibility, backup configurations

---

## 🚀 Features

### ✅ Automated Guardrails
- **Public S3 Detection** - Instantly detects and locks down publicly accessible buckets
- **Encryption Enforcement** - Enables default encryption on non-compliant S3 buckets
- **IAM Policy Validation** - Flags overly permissive wildcard permissions (`*`)
- **Security Group Hardening** - Alerts on 0.0.0.0/0 inbound rules on sensitive ports

### 📊 Monitoring & Alerting
- Real-time CloudWatch dashboards for security metrics
- SNS email/SMS notifications for critical violations
- CloudTrail integration for audit trails and forensics
- Custom CloudWatch Logs for compliance reporting

### 🔧 Remediation Workflows
1. **Detect** - EventBridge rule triggers on CloudTrail events
2. **Analyze** - Lambda function evaluates resource configuration
3. **Remediate** - Automated fix applied (e.g., block public access)
4. **Alert** - Security team notified via SNS
5. **Log** - Action recorded in CloudWatch for compliance

---

## 🛠️ Tech Stack

| Category | Tools |
|----------|-------|
| **Cloud Provider** | AWS (IAM, S3, Lambda, CloudTrail, EventBridge, SNS, CloudWatch) |
| **IaC** | Terraform |
| **Scripting** | Python 3.9+ (Boto3 SDK) |
| **CI/CD** | GitHub Actions |
| **Monitoring** | CloudWatch, CloudTrail |

---

## 📋 Prerequisites

- AWS account with appropriate IAM permissions
- AWS CLI configured (`aws configure`)
- Terraform installed (v1.0+)
- Python 3.9+ with Boto3 library
- Basic understanding of AWS security services

---

## ⚡ Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/deepak-ff/aws-cloud-security-drift-detective.git
cd aws-cloud-security-drift-detective
```

### 2. Set Up AWS Credentials
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

### 3. Deploy Infrastructure with Terraform
```bash
cd terraform
terraform init
terraform plan
terraform apply -auto-approve
```

### 4. Test Misconfiguration Detection
```bash
# Create a public S3 bucket (intentional misconfiguration)
aws s3api create-bucket --bucket test-public-bucket-$(date +%s) --acl public-read

# Watch CloudWatch Logs for automated remediation
aws logs tail /aws/lambda/guardrail-remediation --follow
```

### 5. Verify Remediation
Check your email (SNS) and CloudWatch dashboard to confirm:
- Lambda detected the public bucket
- Public access was automatically blocked
- Alert was sent to security team

---

## 🔧 Setup

### Detailed Deployment Guide

#### Step 1: Environment Preparation

```bash
# Clone the repository
git clone https://github.com/deepak-ff/aws-cloud-security-drift-detective.git
cd aws-cloud-security-drift-detective

# Create Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt
```

#### Step 2: AWS Configuration

```bash
# Configure AWS CLI with your credentials
aws configure
# Enter your AWS Access Key ID
# Enter your AWS Secret Access Key
# Default region: us-east-1 (recommended)
# Default output format: json

# Verify configuration
aws sts get-caller-identity
```

**IAM Permissions Required:**
- `IAM:*` (for creating roles and policies)
- `Lambda:*` (for deploying functions)
- `S3:*` (for bucket operations)
- `CloudTrail:*` (for logging setup)
- `EventBridge:*` (for event rules)
- `SNS:*` (for notifications)
- `CloudWatch:*` (for monitoring)
- `Logs:*` (for CloudWatch Logs)

#### Step 3: Configure Variables

```bash
cd terraform

# Copy example variables
cp terraform.tfvars.example terraform.tfvars

# Edit with your details
nano terraform.tfvars
```

**terraform.tfvars example:**
```hcl
# Project Configuration
project_name = "security-guardrail-lab"
environment  = "dev"
aws_region   = "us-east-1"

# Notification Settings
alert_email  = "your-email@example.com"
alert_phone  = "+1234567890"  # Optional SMS alerts

# Compliance Settings
enable_s3_encryption        = true
enable_s3_versioning        = true
enable_public_access_block  = true
enable_iam_validation       = true

# Cost Control
enable_cost_alerts          = true
monthly_budget_limit        = 50  # USD

# Tags
tags = {
  Project     = "Security-Compliance-Lab"
  Owner       = "Charles-Bucher"
  Environment = "Development"
  Purpose     = "Portfolio-Security-Demo"
}
```

#### Step 4: Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Validate configuration
terraform validate

# Preview changes
terraform plan -out=tfplan

# Deploy (takes ~5-10 minutes)
terraform apply tfplan
```

**Expected Output:**
```
Apply complete! Resources: 27 added, 0 changed, 0 destroyed.

Outputs:

cloudtrail_name = "security-guardrail-lab-trail"
lambda_function_name = "guardrail-remediation-function"
sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:security-alerts"
cloudwatch_dashboard_url = "https://console.aws.amazon.com/cloudwatch/..."
s3_test_bucket = "security-lab-test-bucket-abc123"
```

#### Step 5: Verify Deployment

```bash
# Check Lambda function
aws lambda list-functions --query "Functions[?contains(FunctionName, 'guardrail')]"

# Check CloudTrail status
aws cloudtrail get-trail-status --name security-guardrail-lab-trail

# Check EventBridge rules
aws events list-rules --name-prefix guardrail

# Confirm SNS subscription (check your email)
aws sns list-subscriptions-by-topic --topic-arn <YOUR_SNS_TOPIC_ARN>
```

#### Step 6: Enable SNS Email Notifications

**Important:** Check your email and confirm the SNS subscription to receive alerts!

```
Subject: AWS Notification - Subscription Confirmation
Click the "Confirm subscription" link in the email
```

#### Step 7: Access Monitoring Dashboard

```bash
# Get CloudWatch dashboard URL
terraform output cloudwatch_dashboard_url

# Open in browser or use AWS Console:
# CloudWatch > Dashboards > security-guardrail-lab-dashboard
```

---

## 🎮 Usage

### Practice Scenarios

This lab includes multiple security scenarios to practice detection and remediation workflows. Each scenario simulates real-world misconfigurations.

---

### **Scenario 1: Public S3 Bucket Detection**

**Learning Objective:** Detect and remediate publicly accessible S3 buckets

```bash
# 1. Create an intentionally public bucket
aws s3api create-bucket \
  --bucket public-test-$(date +%s) \
  --acl public-read \
  --region us-east-1

# 2. Watch for automated detection (typically 30-60 seconds)
aws logs tail /aws/lambda/guardrail-remediation --follow

# 3. Verify remediation
aws s3api get-public-access-block --bucket <BUCKET_NAME>

# Expected output: BlockPublicAcls and BlockPublicPolicy = true
```

**What Happens:**
1. CloudTrail logs the `CreateBucket` API call
2. EventBridge rule triggers Lambda function
3. Lambda detects public ACL configuration
4. Lambda applies Block Public Access settings
5. SNS sends alert email with details
6. CloudWatch logs the remediation action

**Check Your Email:** You should receive an alert like:
```
🚨 Security Alert: Public S3 Bucket Detected
Bucket: public-test-1234567890
Action: Block Public Access Applied
Timestamp: 2025-01-02 14:32:15 UTC
```

---

### **Scenario 2: Unencrypted S3 Bucket**

**Learning Objective:** Enforce encryption on all S3 buckets

```bash
# 1. Create bucket without encryption
aws s3api create-bucket \
  --bucket no-encryption-test-$(date +%s) \
  --region us-east-1

# 2. Upload test file (unencrypted)
echo "Sensitive data" > test-file.txt
aws s3 cp test-file.txt s3://<BUCKET_NAME>/

# 3. Wait for guardrail detection (~30 seconds)

# 4. Verify encryption was enabled
aws s3api get-bucket-encryption --bucket <BUCKET_NAME>

# Expected: AES256 encryption enabled automatically
```

**Lambda Action Log:**
```json
{
  "event": "BucketEncryptionMissing",
  "bucket": "no-encryption-test-1234567890",
  "action": "EnableDefaultEncryption",
  "encryption_type": "AES256",
  "status": "SUCCESS"
}
```

---

### **Scenario 3: Overly Permissive IAM Policy**

**Learning Objective:** Detect dangerous wildcard permissions

```bash
# 1. Create IAM policy with wildcard permissions
cat > risky-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": "*"
    }
  ]
}
EOF

# 2. Create and attach policy
aws iam create-policy \
  --policy-name RiskyS3Policy \
  --policy-document file://risky-policy.json

# 3. Check CloudWatch Logs for detection
aws logs filter-log-events \
  --log-group-name /aws/lambda/guardrail-remediation \
  --filter-pattern "WildcardPermission"

# 4. Review alert email for manual remediation steps
```

**Alert Content:**
```
⚠️ IAM Policy Violation Detected
Policy: RiskyS3Policy
Issue: Wildcard action (s3:*) on wildcard resource (*)
Risk Level: HIGH
Recommendation: Apply least privilege principle
Action Required: Manual review needed
```

---

### **Scenario 4: Security Group Open to Internet**

**Learning Objective:** Detect overly permissive security groups

```bash
# 1. Launch EC2 instance with open security group
aws ec2 run-instances \
  --image-id ami-0c55b159cbfafe1f0 \
  --instance-type t2.micro \
  --security-group-ids <CREATE_OPEN_SG_FIRST> \
  --count 1

# 2. Create security group allowing SSH from anywhere
aws ec2 authorize-security-group-ingress \
  --group-id <SG_ID> \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

# 3. Wait for detection alert

# 4. Review remediation recommendation
```

**Guardrail Response:**
```
🔴 Critical: Security Group Misconfiguration
Security Group: sg-abc12345
Rule: SSH (port 22) open to 0.0.0.0/0
Recommended Action: Restrict to corporate IP range
Auto-Remediation: Alert sent (manual review required)
```

---

### **Scenario 5: S3 Versioning Not Enabled**

**Learning Objective:** Enforce versioning for data protection

```bash
# 1. Create bucket without versioning
aws s3api create-bucket \
  --bucket no-versioning-$(date +%s) \
  --region us-east-1

# 2. Wait for guardrail detection

# 3. Verify versioning auto-enabled
aws s3api get-bucket-versioning --bucket <BUCKET_NAME>

# Expected: Status = "Enabled"
```

---

### **Scenario 6: CloudTrail Logging Disabled**

**Learning Objective:** Ensure continuous audit logging

```bash
# 1. Stop CloudTrail (simulate attack/misconfiguration)
aws cloudtrail stop-logging --name security-guardrail-lab-trail

# 2. Immediate detection and auto-restart (~10 seconds)

# 3. Verify CloudTrail restarted
aws cloudtrail get-trail-status --name security-guardrail-lab-trail

# Expected: "IsLogging": true
```

**Critical Alert:**
```
🚨🚨 CRITICAL: CloudTrail Disabled
Trail: security-guardrail-lab-trail
Action: Automatically restarted
Incident Response: Investigate who stopped logging
Forensic Log: Check CloudTrail for StopLogging API call
```

---

### Testing Checklist

Use this checklist to practice all scenarios:

- [ ] **S3 Public Access** - Create public bucket, verify block
- [ ] **S3 Encryption** - Create unencrypted bucket, verify AES-256
- [ ] **S3 Versioning** - Create bucket without versioning, verify enabled
- [ ] **IAM Wildcards** - Create overly permissive policy, verify alert
- [ ] **Security Groups** - Open SSH to 0.0.0.0/0, verify alert
- [ ] **CloudTrail Logging** - Stop CloudTrail, verify auto-restart

---

### Monitoring Your Practice Sessions

#### View Real-Time Logs
```bash
# Follow Lambda execution logs
aws logs tail /aws/lambda/guardrail-remediation --follow --format short

# Filter for specific events
aws logs filter-log-events \
  --log-group-name /aws/lambda/guardrail-remediation \
  --filter-pattern "REMEDIATION"
```

#### Check CloudWatch Metrics
```bash
# View Lambda invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=guardrail-remediation \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

#### Generate Compliance Report
```bash
# Run included compliance report script
python scripts/generate_compliance_report.py --output report.html

# View summary
cat report.html | grep "Total Violations"
```

---

### Cost Tracking

This lab is designed to stay within AWS Free Tier limits:

```bash
# Check current costs
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '1 month ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity MONTHLY \
  --metrics BlendedCost \
  --filter file://cost-filter.json

# Expected monthly cost: $0-5 USD (mostly free tier)
```

**Services Used (Free Tier Eligible):**
- Lambda: 1M requests/month free
- CloudWatch: 10 custom metrics free
- S3: 5GB storage free
- CloudTrail: One trail free
- SNS: 1,000 email notifications free

---

## 📁 Project Structure

```
Security-Compliance-Guardrail-Lab/
│
├── terraform/                  # Infrastructure as Code
│   ├── main.tf                # Core AWS resources
│   ├── variables.tf           # Configuration variables
│   ├── outputs.tf             # Stack outputs
│   └── modules/
│       ├── guardrails/        # Lambda functions and EventBridge rules
│       ├── monitoring/        # CloudWatch dashboards and alarms
│       └── iam/               # IAM roles and policies
│
├── lambda/                    # Python remediation functions
│   ├── s3_guardrails.py       # S3 security automation
│   ├── iam_guardrails.py      # IAM policy validation
│   └── ec2_guardrails.py      # EC2 security group checks
│
├── tests/                     # Unit and integration tests
│   ├── test_s3_remediation.py
│   └── test_event_triggers.py
│
├── docs/                      # Additional documentation
│   ├── ARCHITECTURE.md        # Detailed architecture diagrams
│   ├── RUNBOOK.md            # Incident response procedures
│   └── COMPLIANCE.md         # Compliance framework mapping
│
└── README.md                  # You are here!
```

---

## 🔍 Use Cases Demonstrated

### 1. **S3 Public Access Remediation**
**Scenario**: Developer accidentally makes S3 bucket public  
**Detection**: CloudTrail logs `PutBucketAcl` API call  
**Remediation**: Lambda automatically applies `BlockPublicAccess`  
**Outcome**: Data breach prevented, team notified

### 2. **Unencrypted S3 Bucket**
**Scenario**: Bucket created without default encryption  
**Detection**: EventBridge rule triggers on `CreateBucket`  
**Remediation**: Lambda enables AES-256 encryption  
**Outcome**: Compliance requirement met automatically

### 3. **Overly Permissive IAM Policy**
**Scenario**: IAM role created with `s3:*` on `Resource: *`  
**Detection**: Custom Lambda evaluates IAM policy changes  
**Remediation**: Alert sent to security team for manual review  
**Outcome**: Least privilege principle enforced

---

## 📊 Compliance Frameworks Aligned

This lab demonstrates controls relevant to:

- **NIST Cybersecurity Framework** - Identify, Protect, Detect, Respond, Recover
- **CIS AWS Foundations Benchmark** - Section 2 (Storage), Section 1 (IAM)
- **AWS Well-Architected Framework** - Security Pillar
- **SOC 2 Type II** - Monitoring and incident response capabilities

---

## 🎓 Skills Demonstrated

✅ **Cloud Security** - Implementing preventative and detective controls  
✅ **Automation** - Event-driven workflows with Lambda and EventBridge  
✅ **Infrastructure as Code** - Terraform for repeatable deployments  
✅ **Scripting** - Python with Boto3 for AWS automation  
✅ **Monitoring** - CloudWatch dashboards, logs, and alarms  
✅ **Incident Response** - Automated remediation and alerting  
✅ **Compliance** - Mapping technical controls to frameworks  

---

## 🧪 Testing

Run automated tests to verify guardrails:

```bash
# Install dependencies
pip install -r requirements.txt

# Run unit tests
python -m pytest tests/ -v

# Test S3 remediation workflow
python tests/test_s3_remediation.py
```

**Expected Output**:
```
✓ S3 public access detected
✓ Lambda remediation triggered
✓ Public access blocked
✓ SNS alert sent
```

---

## 📈 Roadmap

### Phase 1 (Current)
- [x] S3 security guardrails
- [x] IAM policy validation
- [x] CloudTrail logging
- [x] Basic Lambda remediation

### Phase 2 (In Progress)
- [ ] EC2 security group automation
- [ ] RDS backup compliance checks
- [ ] Multi-region support
- [ ] Cost optimization alerts

### Phase 3 (Planned)
- [ ] Integration with AWS Security Hub
- [ ] Custom Config Rules
- [ ] Automated threat response with GuardDuty
- [ ] Compliance reporting dashboard

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs via Issues
- Suggest new guardrails or detection rules
- Submit pull requests with improvements

---

## 📞 Connect With Me

Building hands-on AWS cloud projects to break into DevOps and Cloud Security roles.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/charles-bucher-cloud)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/charles-bucher)

💼 **Open to opportunities**: Entry-level Cloud Engineer, DevOps, AWS Security roles  
🎯 **Certifications**: AWS Solutions Architect Associate (in progress)  
📍 **Location**: Largo, Florida | Open to remote

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⭐ Show Your Support

If this project helped you learn AWS security or build your own cloud portfolio, give it a ⭐️!

---

**Built with ☕ and ☁️ by Charles Bucher**  
*Demonstrating real-world cloud security skills through hands-on projects*

## AWS Services Used
- EC2
- VPC
- S3
- IAM
- CloudWatch
- CloudTrail
- GuardDuty
- AWS Config
- Terraform

> Services listed here are actively used in real troubleshooting, monitoring, and remediation workflows.



## Cost Considerations
This project was built with cost-awareness in mind:
- Free tier–safe resource sizing
- Explicit teardown steps included
- Logging scoped to avoid unnecessary ingestion costs
- Monitoring configured to balance visibility vs spend

> Demonstrates real-world cloud cost responsibility.



## Operational Responsibility & Risk Mitigation
This lab simulates production support responsibilities:
- Incident-driven troubleshooting
- Security signal investigation (GuardDuty findings)
- Audit visibility via CloudTrail and Config
- Infrastructure reproducibility using Terraform

This reflects SysOps-style ownership, not tutorial-only usage.

