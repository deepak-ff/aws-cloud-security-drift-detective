# AWS Cloud Security Drift Detective

## Overview

AWS Cloud Security Drift Detective is a cloud security monitoring solution that detects risky configuration changes across AWS environments.

The project analyzes AWS CloudTrail events and identifies security misconfigurations such as:

* IAM Privilege Escalation
* AdministratorAccess Policy Attachments
* Public Security Group Exposure
* Public S3 Access Risks

## Features

* Detects IAM privilege escalation attempts
* Detects AdministratorAccess policy attachments
* Detects SSH (Port 22) exposed to the internet
* Detects risky Security Group changes
* Generates security findings with severity levels
* Provides remediation recommendations
* Supports local testing using sample CloudTrail events

## Technology Stack

* Python
* AWS CloudTrail
* AWS Lambda
* Amazon EventBridge
* Amazon SNS

## Project Structure

aws-cloud-security-drift-detective/

├── detector.py

├── lambda_function.py

├── requirements.txt

├── scripts/

│ └── local_test.py

├── samples/

│ ├── sample_iam_event.json

│ ├── sample_s3_event.json

│ └── sample_sg_event.json

## Sample Findings

Critical – AdministratorAccess Policy Attached

High – SSH Open to Internet (0.0.0.0/0)

## Future Improvements

* Public S3 Bucket Detection
* Root User Activity Detection
* MFA Disabled Detection
* CloudTrail Tampering Detection
* HTML Security Dashboard

##Architecture Diagram

```mermaid
flowchart TD

    A[Developer / Admin Action] --> B[CloudTrail Event]

    B --> C[Amazon EventBridge]

    C --> D[AWS Lambda<br/>Cloud Security Drift Detector]

    D --> E[AdministratorAccess Detection]
    D --> F[SSH Open to Internet Detection]
    D --> G[S3 Security Policy Analysis]

    E --> H[Risk Classification]

    F --> H

    G --> H

    H --> I[Critical / High / Medium Findings]

    I --> J[SNS Email Alerts]

    I --> K[JSON Security Reports]

```

##Screenshots

Screenshot 1 – IAM Detection

<img width="1490" height="387" alt="image" src="https://github.com/user-attachments/assets/f803ab4b-a019-4a54-9941-5313f72eae29" />

Screenshot 2 – Security Group Detection

<img width="1483" height="512" alt="image" src="https://github.com/user-attachments/assets/4ff6d43c-3cca-4926-9697-5a0f297bc95a" />

Screenshot 3 – Full Output

<img width="1610" height="893" alt="image" src="https://github.com/user-attachments/assets/998ced7f-f746-4b14-b324-75d03a255223" />

## Author

Deepak Sundhar B
